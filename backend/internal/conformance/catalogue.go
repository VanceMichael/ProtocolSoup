package conformance

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// ExplainerSource supplies human-authored explainer markdown for a
// requirement ID. The palette service implements it from spec-assertion
// artefacts; a nil source means no requirement has an explainer.
type ExplainerSource interface {
	Explainer(id string) (markdown string, ok bool)
}

// Catalogue joins the embedded registry with the currently active
// conformance report generation and the serving build's commit. It is the
// single source for everything a requirement page may assert: a verdict is
// only exposed when the active generation provably describes the running
// build.
//
// The active generation is an immutable snapshot replaced atomically by
// Reload (SIGHUP). Handlers snapshot it once per request, so every response
// comes from one complete generation and reloads never produce mixed views
// or blank windows: a rejected candidate leaves the previous generation
// active.
type Catalogue struct {
	registry    Registry
	reportPath  string
	buildCommit string
	explainers  ExplainerSource

	active   atomic.Pointer[generation]
	reloadMu sync.Mutex
	nextGenID uint64
	state    atomic.Pointer[reloadState]

	specs     []Specification          // specs with at least one requirement, registry order
	specByID  map[string]Specification // canonical spec ID
	bySpec    map[string][]Requirement // canonical spec ID -> requirements in spec order
	byLowerID map[string]Requirement   // lowercase requirement ID -> requirement
}

// LoadReport reads a conformance report written by cmd/conformance-report.
func LoadReport(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report Report
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("decode conformance report %s: %w", path, err)
	}
	return &report, nil
}

// newCatalogue builds the registry-derived, reload-independent indexes.
func newCatalogue(registry Registry, buildCommit string, explainers ExplainerSource) *Catalogue {
	c := &Catalogue{
		registry:    registry,
		buildCommit: strings.TrimSpace(buildCommit),
		explainers:  explainers,
		specByID:    make(map[string]Specification, len(registry.Specifications)),
		bySpec:      make(map[string][]Requirement),
		byLowerID:   make(map[string]Requirement, len(registry.Requirements)),
	}
	for _, req := range registry.Requirements {
		c.byLowerID[strings.ToLower(req.ID)] = req
		c.bySpec[req.Specification] = append(c.bySpec[req.Specification], req)
	}
	for _, spec := range registry.Specifications {
		reqs := c.bySpec[spec.ID]
		if len(reqs) == 0 {
			continue
		}
		sort.SliceStable(reqs, func(i, j int) bool {
			if cmp := CompareSections(reqs[i].Section, reqs[j].Section); cmp != 0 {
				return cmp < 0
			}
			return reqs[i].ID < reqs[j].ID
		})
		c.bySpec[spec.ID] = reqs
		c.specs = append(c.specs, spec)
		c.specByID[spec.ID] = spec
	}
	return c
}

// NewCatalogue builds a catalogue from a static report. report and
// explainers may be nil. A report that does not describe buildCommit (wrong
// commit, dirty tree) is simply not activated, so pages render "Not
// evaluated for this build".
func NewCatalogue(registry Registry, report *Report, buildCommit string, explainers ExplainerSource) *Catalogue {
	c := newCatalogue(registry, buildCommit, explainers)
	if reportMatchesBuild(report, c.buildCommit) {
		c.active.Store(newGeneration(1, registry, report, c.buildCommit))
		c.nextGenID = 1
	}
	return c
}

// Registry returns the underlying registry.
func (c *Catalogue) Registry() Registry { return c.registry }

// BuildCommit returns the serving build's commit, possibly empty.
func (c *Catalogue) BuildCommit() string { return c.buildCommit }

// Report returns the active report, or nil when no generation is active.
// Callers must check ReportValid before presenting any verdict from it.
func (c *Catalogue) Report() *Report {
	if g := c.active.Load(); g != nil {
		return g.report
	}
	return nil
}

// ReportValid reports whether the active generation describes the running
// build: it exists, was generated from a clean tree, and its commit equals
// the build commit with both non-empty.
func (c *Catalogue) ReportValid() bool {
	return c.active.Load().isValid()
}

// LaunchGateOpen is true when the active generation is valid and no
// MUST-family requirement has a verdict of FAIL, MISSING_TEST or CHECK.
func (c *Catalogue) LaunchGateOpen() bool {
	return c.active.Load().isGateOpen()
}

// Requirement resolves a requirement ID case-insensitively and returns the
// canonical registry entry.
func (c *Catalogue) Requirement(id string) (Requirement, bool) {
	req, ok := c.byLowerID[strings.ToLower(strings.TrimSpace(id))]
	return req, ok
}

// Result returns the active generation's result for a requirement. It is
// only populated when ReportValid is true, which implements the
// no-fabricated-verdicts rule.
func (c *Catalogue) Result(id string) (RequirementResult, bool) {
	return c.resultFor(c.active.Load(), id)
}

func (c *Catalogue) resultFor(g *generation, id string) (RequirementResult, bool) {
	if !g.isValid() {
		return RequirementResult{}, false
	}
	req, ok := c.Requirement(id)
	if !ok {
		return RequirementResult{}, false
	}
	result, ok := g.resultByID[req.ID]
	return result, ok
}

// Explainer returns the human-authored explainer for a requirement, if any.
func (c *Catalogue) Explainer(id string) (string, bool) {
	if c.explainers == nil {
		return "", false
	}
	req, ok := c.Requirement(id)
	if !ok {
		return "", false
	}
	return c.explainers.Explainer(strings.ToLower(req.ID))
}

// Indexable reports whether a requirement page may be indexed: the launch
// gate is open, its verdict is PASS, DEVIATION or N/A, and an explainer
// exists. Indexability is derived from evidence, never configured.
func (c *Catalogue) Indexable(id string) bool {
	return c.indexableFor(c.active.Load(), id)
}

func (c *Catalogue) indexableFor(g *generation, id string) bool {
	if !g.isGateOpen() {
		return false
	}
	result, ok := c.resultFor(g, id)
	if !ok {
		return false
	}
	switch result.Verdict {
	case VerdictPass, VerdictDeviation, VerdictNotApply:
	default:
		return false
	}
	_, hasExplainer := c.Explainer(id)
	return hasExplainer
}

// Specifications returns the specifications that have at least one
// requirement, in registry order.
func (c *Catalogue) Specifications() []Specification {
	return append([]Specification(nil), c.specs...)
}

// Specification resolves a spec ID case-insensitively. Specifications with
// zero requirements are not found.
func (c *Catalogue) Specification(id string) (Specification, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, spec := range c.specs {
		if strings.ToLower(spec.ID) == id {
			return spec, true
		}
	}
	return Specification{}, false
}

// Requirements returns a specification's requirements ordered by
// CompareSections, then by ID.
func (c *Catalogue) Requirements(specID string) []Requirement {
	spec, ok := c.Specification(specID)
	if !ok {
		return nil
	}
	return append([]Requirement(nil), c.bySpec[spec.ID]...)
}

// SpecIndexable reports whether a specification index page may be indexed:
// the launch gate is open and at least one of its requirements is indexable.
func (c *Catalogue) SpecIndexable(specID string) bool {
	return c.specIndexableFor(c.active.Load(), specID)
}

func (c *Catalogue) specIndexableFor(g *generation, specID string) bool {
	if !g.isGateOpen() {
		return false
	}
	for _, req := range c.Requirements(specID) {
		if c.indexableFor(g, req.ID) {
			return true
		}
	}
	return false
}

// Neighbours returns the same-section siblings of a requirement (excluding
// itself) and its previous and next requirement in specification order.
func (c *Catalogue) Neighbours(id string) (siblings []Requirement, previous, next *Requirement) {
	req, ok := c.Requirement(id)
	if !ok {
		return nil, nil, nil
	}
	ordered := c.bySpec[req.Specification]
	for i := range ordered {
		other := ordered[i]
		if other.ID == req.ID {
			if i > 0 {
				prev := ordered[i-1]
				previous = &prev
			}
			if i+1 < len(ordered) {
				nxt := ordered[i+1]
				next = &nxt
			}
			continue
		}
		if other.Section == req.Section {
			siblings = append(siblings, other)
		}
	}
	return siblings, previous, next
}

// VerdictSummary counts verdicts across a specification's requirements in
// the active generation. It returns nil when that generation is not valid.
func (c *Catalogue) VerdictSummary(specID string) map[Verdict]int {
	return c.verdictSummaryFor(c.active.Load(), specID)
}

func (c *Catalogue) verdictSummaryFor(g *generation, specID string) map[Verdict]int {
	if !g.isValid() {
		return nil
	}
	summary := make(map[Verdict]int)
	for _, req := range c.Requirements(specID) {
		if result, ok := g.resultByID[req.ID]; ok {
			summary[result.Verdict]++
		}
	}
	return summary
}

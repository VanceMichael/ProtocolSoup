package conformance

import (
	"fmt"
	"strings"
	"time"
)

// generation is one immutable, fully resolved view of a conformance report.
// After a generation is published through Catalogue.active it is never
// mutated, so an HTTP handler that snapshots the pointer once builds its
// entire response from either that complete generation or a newer one, even
// while a SIGHUP reload is publishing a replacement concurrently.
type generation struct {
	id         uint64
	report     *Report
	resultByID map[string]RequirementResult
	valid      bool
	gateOpen   bool
}

func newGeneration(id uint64, registry Registry, report *Report, buildCommit string) *generation {
	g := &generation{id: id, report: report}
	results := make(map[string]RequirementResult, len(report.Requirements))
	for _, result := range report.Requirements {
		results[result.ID] = result
	}
	g.resultByID = results

	commit := strings.TrimSpace(report.Commit)
	g.valid = !report.Dirty && commit != "" && buildCommit != "" && commit == buildCommit
	if !g.valid {
		return g
	}
	g.gateOpen = true
	for _, req := range registry.Requirements {
		if !IsMustFamily(req.Level) {
			continue
		}
		result, ok := results[req.ID]
		if !ok {
			g.gateOpen = false
			break
		}
		switch result.Verdict {
		case VerdictFail, VerdictMissingTest, VerdictCheck:
			g.gateOpen = false
		}
	}
	return g
}

func (g *generation) isValid() bool { return g != nil && g.valid }

func (g *generation) isGateOpen() bool { return g != nil && g.gateOpen }

// provenance returns the report commit and generation time exposed to
// clients. Both are empty for inactive or invalid generations.
func (g *generation) provenance() (commit, generatedAt string) {
	if !g.isValid() {
		return "", ""
	}
	return g.report.Commit, g.report.GeneratedAt
}

// ReloadResult describes one Catalogue.Reload attempt.
type ReloadResult struct {
	// Configured is false when no report path is configured; the attempt was
	// a no-op and no error was recorded.
	Configured bool
	// Activated is true when a new generation became active.
	Activated bool
	// GenerationID identifies the active generation after the attempt: 0 when
	// no valid report has ever been active.
	GenerationID uint64
	Commit       string
	GeneratedAt  string
	CheckedAt    time.Time
	// Err is set when the candidate could not be parsed or did not describe
	// this build. The previously active generation stays in service.
	Err error
}

// Status is the operator-visible reload state surfaced on /health.
type Status struct {
	Configured     bool
	Active         bool
	Generation     uint64
	ReportValid    bool
	LaunchGateOpen bool
	Commit         string
	GeneratedAt    string
	LastReloadAt   time.Time
	// LastError describes the most recent rejected reload and is empty after
	// a successful activation.
	LastError   string
	LastErrorAt time.Time
}

// reloadState is replaced atomically on every reload attempt.
type reloadState struct {
	lastReloadAt time.Time
	lastError    string
	lastErrorAt  time.Time
}

// NewReloadableCatalogue builds a catalogue whose active report can be
// replaced with Reload (driven by SIGHUP). The initial generation is empty;
// callers invoke Reload once to load the report configured at reportPath,
// which gives startup and signal-driven reloads identical candidate rules.
func NewReloadableCatalogue(registry Registry, reportPath, buildCommit string, explainers ExplainerSource) *Catalogue {
	c := newCatalogue(registry, buildCommit, explainers)
	c.reportPath = reportPath
	c.state.Store(&reloadState{})
	return c
}

// ReportPath returns the report file Reload reads, empty when unconfigured.
func (c *Catalogue) ReportPath() string { return c.reportPath }

// Reload reads and validates the configured report candidate and, only when
// it parses, was generated from a clean tree, and its commit equals
// BUILD_COMMIT, atomically publishes it as a new active generation. A
// rejected candidate never disturbs the active generation: its verdicts,
// launch gate and index results keep serving until a later reload activates
// a valid replacement. Reload is safe for concurrent use; attempts are
// serialized and the last successful generation always wins.
func (c *Catalogue) Reload() ReloadResult {
	now := time.Now().UTC()
	result := ReloadResult{CheckedAt: now, GenerationID: c.ActiveGeneration(), Configured: c.reportPath != ""}
	if c.reportPath == "" {
		return result
	}

	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()

	report, err := LoadReport(c.reportPath)
	if err != nil {
		return c.rejectReload(now, fmt.Errorf("load conformance report %s: %w", c.reportPath, err))
	}
	if reason := reportBuildMismatch(report, c.buildCommit); reason != "" {
		return c.rejectReload(now, fmt.Errorf("conformance report %s rejected: %s", c.reportPath, reason))
	}

	c.nextGenID++
	g := newGeneration(c.nextGenID, c.registry, report, c.buildCommit)
	c.active.Store(g)
	// A successful activation clears the last reload error: operators see
	// the new generation id to know recovery happened.
	c.state.Store(&reloadState{lastReloadAt: now})
	return ReloadResult{
		Configured:   true,
		Activated:    true,
		GenerationID: g.id,
		Commit:       report.Commit,
		GeneratedAt:  report.GeneratedAt,
		CheckedAt:    now,
	}
}

func (c *Catalogue) rejectReload(now time.Time, err error) ReloadResult {
	c.state.Store(&reloadState{lastReloadAt: now, lastError: err.Error(), lastErrorAt: now})
	return ReloadResult{
		Configured:   true,
		GenerationID: c.ActiveGeneration(),
		CheckedAt:    now,
		Err:          err,
	}
}

// reportBuildMismatch returns a non-empty rejection reason when report
// cannot serve as evidence for buildCommit.
func reportBuildMismatch(report *Report, buildCommit string) string {
	if report == nil {
		return "report is empty"
	}
	if report.Dirty {
		return "it was generated from a dirty working tree"
	}
	commit := strings.TrimSpace(report.Commit)
	switch {
	case commit == "":
		return "it carries no source commit"
	case buildCommit == "":
		return "the server has no BUILD_COMMIT to bind evidence to"
	case commit != buildCommit:
		return fmt.Sprintf("report commit %s does not match BUILD_COMMIT %s", commit, buildCommit)
	}
	return ""
}

// reportMatchesBuild reports whether a statically supplied report is valid
// for buildCommit; it mirrors the Reload candidate rules.
func reportMatchesBuild(report *Report, buildCommit string) bool {
	return reportBuildMismatch(report, buildCommit) == ""
}

// ActiveGeneration returns the sequence number of the active generation, or 0
// when no valid report has ever been activated.
func (c *Catalogue) ActiveGeneration() uint64 {
	if g := c.active.Load(); g != nil {
		return g.id
	}
	return 0
}

// Status returns a consistent snapshot of activity, generation and the most
// recent reload outcome for /health.
func (c *Catalogue) Status() Status {
	status := Status{Configured: c.reportPath != "", Generation: c.ActiveGeneration()}
	if g := c.active.Load(); g != nil {
		status.Active = true
		status.ReportValid = g.valid
		status.LaunchGateOpen = g.gateOpen
		status.Commit = g.report.Commit
		status.GeneratedAt = g.report.GeneratedAt
	}
	if state := c.state.Load(); state != nil {
		status.LastReloadAt = state.lastReloadAt
		status.LastError = state.lastError
		status.LastErrorAt = state.lastErrorAt
	}
	return status
}

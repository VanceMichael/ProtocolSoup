package conformance

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	reportAGeneratedAt = "2026-09-22T00:00:00Z"
	reportBGeneratedAt = "2026-10-01T00:00:00Z"
)

// reportA is the all-passing baseline; reportB closes the launch gate by
// failing MUST requirement AL-010 and carries a distinct generation time.
func reloadReports(registry Registry) (*Report, *Report) {
	a := catalogueReport(registry, nil)
	a.GeneratedAt = reportAGeneratedAt
	b := catalogueReport(registry, map[string]Verdict{"AL-010": VerdictFail})
	b.GeneratedAt = reportBGeneratedAt
	return a, b
}

func writeReportFile(t *testing.T, path string, report *Report) {
	t.Helper()
	if err := WriteReport(path, *report); err != nil {
		t.Fatalf("write report: %v", err)
	}
}

func newReloadCatalogue(t *testing.T, path string, explainers ExplainerSource) (*Catalogue, Registry) {
	t.Helper()
	registry := catalogueRegistry()
	return NewReloadableCatalogue(registry, path, testBuildCommit, explainers), registry
}

func serveRaw(t *testing.T, c *Catalogue, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	c.Routes().ServeHTTP(recorder, request)
	return recorder
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v\n%s", err, recorder.Body.String())
	}
	return body
}

func TestWriteReportAtomicallyReplacesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "report.json")
	registry := catalogueRegistry()
	reportA, reportB := reloadReports(registry)

	if err := WriteReport(path, *reportA); err != nil {
		t.Fatalf("WriteReport: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("mode = %o, want 0644", mode)
	}
	loaded, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if loaded.GeneratedAt != reportAGeneratedAt {
		t.Fatalf("generated_at = %q", loaded.GeneratedAt)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 || entries[0].Name() != "report.json" {
		t.Fatalf("temp files left behind: %v (err=%v)", entries, err)
	}

	if err := WriteReport(path, *reportB); err != nil {
		t.Fatalf("WriteReport replacement: %v", err)
	}
	reloaded, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport after replace: %v", err)
	}
	if reloaded.GeneratedAt != reportBGeneratedAt {
		t.Fatalf("stale file served after replace: %q", reloaded.GeneratedAt)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("temp files left behind after replace: %v", entries)
	}
}

func TestWriteReportFailureLeavesExistingFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "report.json")
	original := []byte(`{"schema_version":1}` + "\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// Deterministic failure on every platform (including tests run as root):
	// a parent path component is an existing regular file, so the temp file
	// cannot be created. Nothing may be created and the sibling target stays
	// byte-for-byte intact.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	blockedPath := filepath.Join(blocker, "nested", "report.json")
	if err := WriteReport(blockedPath, Report{}); err == nil {
		t.Fatal("WriteReport into a file-as-directory succeeded; want failure")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("target altered by failed write:\nwant %q\ngot  %q", original, got)
	}
	if _, err := os.Stat(blockedPath); err == nil {
		t.Fatalf("blocked path created unexpectedly: %v", blockedPath)
	}
}

func TestWriteReportUnwritableDirectoryKeepsTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "report.json")
	original := []byte(`{"old":true}` + "\n")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}

	registry := catalogueRegistry()
	if err := WriteReport(target, *catalogueReport(registry, nil)); err == nil {
		t.Fatal("WriteReport into a read-only directory succeeded; want failure")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read preserved target: %v", err)
	}
	if string(got) != string(original) {
		t.Fatalf("target replaced despite write failure:\nwant %q\ngot  %q", original, got)
	}
}

func TestReloadActivatesFirstValidReportAfterMissingStartup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	c, registry := newReloadCatalogue(t, path, mapExplainers{"al-010": "# x", "be-001": "# y"})
	reportA, _ := reloadReports(registry)

	outcome := c.Reload()
	if outcome.Configured != true || outcome.Activated || outcome.Err == nil || outcome.GenerationID != 0 {
		t.Fatalf("startup reload of missing file = %+v, want rejected, gen 0", outcome)
	}
	status := c.Status()
	if status.Active || status.Generation != 0 || status.LastError == "" || !status.Configured {
		t.Fatalf("status after missing startup = %+v", status)
	}
	recorder := serveRaw(t, c, "/specs", nil)
	body := decodeBody(t, recorder)
	if body["report_valid"] != false || body["launch_gate_open"] != false {
		t.Fatalf("not-evaluated response = %+v", body)
	}
	if _, present := body["commit"]; present {
		t.Fatal("commit must be absent before first activation")
	}
	if recorder.Header().Get("ETag") != `"conformance-g0"` {
		t.Fatalf("ETag = %q, want conformance-g0", recorder.Header().Get("ETag"))
	}

	writeReportFile(t, path, reportA)
	outcome = c.Reload()
	if !outcome.Activated || outcome.GenerationID != 1 || outcome.Err != nil {
		t.Fatalf("first activation = %+v", outcome)
	}
	recorder = serveRaw(t, c, "/specs", nil)
	body = decodeBody(t, recorder)
	if body["report_valid"] != true || body["commit"] != testBuildCommit || body["generated_at"] != reportAGeneratedAt {
		t.Fatalf("activated response = %+v", body)
	}
	if recorder.Header().Get("ETag") != `"conformance-g1"` {
		t.Fatalf("ETag = %q, want conformance-g1", recorder.Header().Get("ETag"))
	}
}

func TestReloadRejectsBadCandidatesButKeepsLastValidGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	c, registry := newReloadCatalogue(t, path, mapExplainers{"al-010": "# x", "be-001": "# y"})
	reportA, reportB := reloadReports(registry)
	writeReportFile(t, path, reportA)
	if outcome := c.Reload(); !outcome.Activated || outcome.GenerationID != 1 {
		t.Fatalf("initial activation = %+v", outcome)
	}

	// Every rejection must leave generation 1's verdicts, gate, provenance,
	// index results and ETag exactly where they were.
	reject := func(name string, candidate []byte, wantErr string) {
		t.Helper()
		if err := os.WriteFile(path, candidate, 0o644); err != nil {
			t.Fatal(err)
		}
		outcome := c.Reload()
		if outcome.Activated || outcome.Err == nil || outcome.GenerationID != 1 {
			t.Fatalf("%s: outcome = %+v, want rejected, gen 1 retained", name, outcome)
		}
		if !strings.Contains(outcome.Err.Error(), wantErr) {
			t.Fatalf("%s: error %q does not contain %q", name, outcome.Err, wantErr)
		}
		status := c.Status()
		if !status.Active || status.Generation != 1 || status.LastError == "" {
			t.Fatalf("%s: status = %+v, want gen 1 with last error", name, status)
		}
		assertGenerationA(t, c, name)
	}

	t.Run("corrupt JSON", func(t *testing.T) { reject("corrupt", []byte("{not json"), "decode") })
	t.Run("missing file", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		outcome := c.Reload()
		if outcome.Activated || outcome.GenerationID != 1 || outcome.Err == nil {
			t.Fatalf("missing: outcome = %+v", outcome)
		}
		assertGenerationA(t, c, "missing")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("dirty tree", func(t *testing.T) {
		dirty := *reportA
		dirty.Dirty = true
		data, _ := json.Marshal(dirty)
		reject("dirty", data, "dirty")
	})
	t.Run("commit mismatch", func(t *testing.T) {
		mismatch := *reportA
		mismatch.Commit = "ffffffffffffffffffffffffffffffffffffffff"
		data, _ := json.Marshal(mismatch)
		reject("mismatch", data, "does not match BUILD_COMMIT")
	})
	t.Run("empty report commit", func(t *testing.T) {
		noCommit := *reportA
		noCommit.Commit = ""
		data, _ := json.Marshal(noCommit)
		reject("empty commit", data, "no source commit")
	})

	// Repair on the next signal activates generation 2 and clears the error.
	writeReportFile(t, path, reportB)
	outcome := c.Reload()
	if !outcome.Activated || outcome.GenerationID != 2 || outcome.Err != nil {
		t.Fatalf("recovery activation = %+v", outcome)
	}
	status := c.Status()
	if status.Generation != 2 || status.LastError != "" || !status.Active || status.LaunchGateOpen {
		t.Fatalf("status after recovery = %+v, want gen 2, gate closed, error cleared", status)
	}
	assertGenerationB(t, c)
}

// assertGenerationA asserts every endpoint still serves the complete
// generation-1 report A snapshot.
func assertGenerationA(t *testing.T, c *Catalogue, phase string) {
	t.Helper()

	recorder := serveRaw(t, c, "/specs", nil)
	if recorder.Header().Get("ETag") != `"conformance-g1"` {
		t.Fatalf("%s: ETag = %q, want g1", phase, recorder.Header().Get("ETag"))
	}
	body := decodeBody(t, recorder)
	if body["report_valid"] != true || body["launch_gate_open"] != true ||
		body["commit"] != testBuildCommit || body["generated_at"] != reportAGeneratedAt {
		t.Fatalf("%s: specs header fields = %+v", phase, body)
	}
	alpha := body["specs"].([]any)[0].(map[string]any)
	if alpha["verdicts"].(map[string]any)["PASS"] != float64(4) || alpha["indexable"] != true {
		t.Fatalf("%s: alpha summary = %+v", phase, alpha)
	}

	recorder = serveRaw(t, c, "/specs/alpha", nil)
	body = decodeBody(t, recorder)
	if body["generated_at"] != reportAGeneratedAt || body["launch_gate_open"] != true {
		t.Fatalf("%s: spec detail mixed generations: %+v", phase, body)
	}
	for _, row := range body["requirements"].([]any) {
		r := row.(map[string]any)
		if r["id"] == "AL-010" && r["verdict"] != "PASS" {
			t.Fatalf("%s: AL-010 verdict = %v, want PASS", phase, r["verdict"])
		}
	}

	recorder = serveRaw(t, c, "/requirements/al-010", nil)
	body = decodeBody(t, recorder)
	if body["verdict"] != "PASS" || body["commit"] != testBuildCommit || body["generated_at"] != reportAGeneratedAt {
		t.Fatalf("%s: requirement = %+v", phase, body)
	}
	if body["source_base_url"] != SourceRepository+"/blob/"+testBuildCommit+"/" {
		t.Fatalf("%s: source_base_url = %v", phase, body["source_base_url"])
	}
	if body["indexable"] != true {
		t.Fatalf("%s: AL-010 must stay indexable in generation 1", phase)
	}

	recorder = serveRaw(t, c, "/sitemap", nil)
	var entries []SitemapEntry
	if err := json.Unmarshal(recorder.Body.Bytes(), &entries); err != nil {
		t.Fatalf("%s: sitemap decode: %v", phase, err)
	}
	if len(entries) != 4 {
		t.Fatalf("%s: sitemap = %+v, want 4 entries", phase, entries)
	}
	for _, entry := range entries {
		if entry.LastMod != reportAGeneratedAt {
			t.Fatalf("%s: sitemap lastmod %q from another generation", phase, entry.LastMod)
		}
	}
}

// assertGenerationB asserts the repaired generation 2 (gate closed) is served
// whole on every endpoint.
func assertGenerationB(t *testing.T, c *Catalogue) {
	t.Helper()

	recorder := serveRaw(t, c, "/specs", nil)
	if recorder.Header().Get("ETag") != `"conformance-g2"` {
		t.Fatalf("ETag = %q, want g2", recorder.Header().Get("ETag"))
	}
	body := decodeBody(t, recorder)
	if body["launch_gate_open"] != false || body["generated_at"] != reportBGeneratedAt {
		t.Fatalf("generation 2 specs = %+v", body)
	}
	alpha := body["specs"].([]any)[0].(map[string]any)
	verdicts := alpha["verdicts"].(map[string]any)
	if verdicts["PASS"] != float64(3) || verdicts["FAIL"] != float64(1) || alpha["indexable"] != false {
		t.Fatalf("generation 2 alpha = %+v", alpha)
	}

	recorder = serveRaw(t, c, "/requirements/al-010", nil)
	body = decodeBody(t, recorder)
	if body["verdict"] != "FAIL" || body["indexable"] != false ||
		body["commit"] != testBuildCommit || body["generated_at"] != reportBGeneratedAt {
		t.Fatalf("generation 2 requirement = %+v", body)
	}

	recorder = serveRaw(t, c, "/sitemap", nil)
	if strings.TrimSpace(recorder.Body.String()) != "[]" {
		t.Fatalf("generation 2 sitemap = %q, want []", recorder.Body.String())
	}
	if recorder.Header().Get("ETag") != `"conformance-g2"` {
		t.Fatalf("sitemap ETag = %q, want g2", recorder.Header().Get("ETag"))
	}
}

func TestReloadNotConfiguredIsNoErrorNoop(t *testing.T) {
	registry := catalogueRegistry()
	c := NewReloadableCatalogue(registry, "", testBuildCommit, nil)
	if c.ReportPath() != "" {
		t.Fatalf("ReportPath = %q, want empty", c.ReportPath())
	}
	for i := 0; i < 2; i++ {
		outcome := c.Reload()
		if outcome.Configured || outcome.Activated || outcome.Err != nil {
			t.Fatalf("reload %d = %+v, want unconfigured no-op", i, outcome)
		}
	}
	if status := c.Status(); status.Configured || status.Active || status.LastError != "" {
		t.Fatalf("status = %+v, want unconfigured and clean", status)
	}
	recorder := serveRaw(t, c, "/specs", nil)
	if recorder.Header().Get("ETag") != `"conformance-g0"` {
		t.Fatalf("ETag = %q", recorder.Header().Get("ETag"))
	}
}

func TestReloadWithoutBuildCommitRejects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	registry := catalogueRegistry()
	reportA, _ := reloadReports(registry)
	writeReportFile(t, path, reportA)

	c := NewReloadableCatalogue(registry, path, "", nil)
	outcome := c.Reload()
	if outcome.Activated || outcome.Err == nil {
		t.Fatalf("reload without BUILD_COMMIT = %+v", outcome)
	}
	if !strings.Contains(outcome.Err.Error(), "BUILD_COMMIT") {
		t.Fatalf("error = %q", outcome.Err)
	}
	if c.ActiveGeneration() != 0 || c.ReportValid() {
		t.Fatal("candidate without BUILD_COMMIT must not activate")
	}
}

func TestGenerationETagConditionalRequests(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	c, registry := newReloadCatalogue(t, path, nil)
	reportA, reportB := reloadReports(registry)
	writeReportFile(t, path, reportA)
	if outcome := c.Reload(); !outcome.Activated {
		t.Fatal(outcome.Err)
	}

	endpoints := []string{"/specs", "/specs/alpha", "/requirements/al-010", "/sitemap"}
	for _, endpoint := range endpoints {
		recorder := serveRaw(t, c, endpoint, nil)
		if recorder.Code != http.StatusOK || recorder.Header().Get("ETag") != `"conformance-g1"` {
			t.Fatalf("%s: code=%d ETag=%q", endpoint, recorder.Code, recorder.Header().Get("ETag"))
		}
		recorder = serveRaw(t, c, endpoint, map[string]string{"If-None-Match": `"conformance-g1"`})
		if recorder.Code != http.StatusNotModified || recorder.Body.Len() != 0 ||
			recorder.Header().Get("ETag") != `"conformance-g1"` {
			t.Fatalf("%s: conditional = code %d, body %q, etag %q", endpoint, recorder.Code, recorder.Body.String(), recorder.Header().Get("ETag"))
		}
		recorder = serveRaw(t, c, endpoint, map[string]string{"If-None-Match": `"conformance-g0", "conformance-g1"`})
		if recorder.Code != http.StatusNotModified {
			t.Fatalf("%s: multi-tag conditional = %d, want 304", endpoint, recorder.Code)
		}
		recorder = serveRaw(t, c, endpoint, map[string]string{"If-None-Match": "*"})
		if recorder.Code != http.StatusNotModified {
			t.Fatalf("%s: wildcard conditional = %d, want 304", endpoint, recorder.Code)
		}
	}

	// A rejected reload keeps the previous validator conditional clients hold.
	if err := os.WriteFile(path, []byte("broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if outcome := c.Reload(); outcome.Err == nil {
		t.Fatal("corrupt reload unexpectedly succeeded")
	}
	recorder := serveRaw(t, c, "/specs", map[string]string{"If-None-Match": `"conformance-g1"`})
	if recorder.Code != http.StatusNotModified {
		t.Fatalf("conditional after rejected reload = %d, want 304", recorder.Code)
	}

	// After repair the old validator misses and the new one hits.
	writeReportFile(t, path, reportB)
	if outcome := c.Reload(); !outcome.Activated || outcome.GenerationID != 2 {
		t.Fatalf("recovery = %+v", outcome)
	}
	recorder = serveRaw(t, c, "/specs", map[string]string{"If-None-Match": `"conformance-g1"`})
	if recorder.Code != http.StatusOK || recorder.Body.Len() == 0 {
		t.Fatalf("old validator after new generation = code %d", recorder.Code)
	}
	recorder = serveRaw(t, c, "/specs", map[string]string{"If-None-Match": `"conformance-g2"`})
	if recorder.Code != http.StatusNotModified {
		t.Fatalf("new validator = %d, want 304", recorder.Code)
	}
}

// TestReloadAndRequestsNeverMixGenerations hammers every endpoint while one
// goroutine alternates two distinct, deterministically-known valid reports.
// Every single response must be entirely generation A or entirely generation
// B: provenance, gate, summary, verdicts, sitemap lastmod and the ETag
// sequence number have to agree. Run with -race to also cover the swap.
func TestReloadAndRequestsNeverMixGenerations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	c, registry := newReloadCatalogue(t, path, mapExplainers{"al-010": "# x", "be-001": "# y"})
	reportA, reportB := reloadReports(registry)
	writeReportFile(t, path, reportA)
	if outcome := c.Reload(); !outcome.Activated {
		t.Fatal(outcome.Err)
	}

	const reloadCycles = 50
	const readerGoroutines = 8
	const requestsPerReader = 100

	// request fires a request without any test-fatal calls, so it is safe to
	// use from worker goroutines.
	request := func(target string) (int, http.Header, []byte) {
		recorder := httptest.NewRecorder()
		c.Routes().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, target, nil))
		return recorder.Code, recorder.Header(), recorder.Body.Bytes()
	}
	etagGen := func(etag string) (uint64, bool) {
		number, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(etag, `"conformance-g`), `"`), 10, 64)
		return number, err == nil
	}

	start := make(chan struct{})
	var writers sync.WaitGroup
	writers.Add(1)
	go func() {
		defer writers.Done()
		<-start
		for i := 0; i < reloadCycles; i++ {
			next := reportB
			if i%2 == 1 {
				next = reportA
			}
			if err := WriteReport(path, *next); err != nil {
				t.Errorf("write candidate %d: %v", i, err)
				return
			}
			outcome := c.Reload()
			if !outcome.Activated {
				t.Errorf("reload %d rejected: %v", i, outcome.Err)
				return
			}
		}
	}()

	var failuresMu sync.Mutex
	var failures []string
	fail := func(format string, args ...any) {
		failuresMu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		failuresMu.Unlock()
	}

	var readers sync.WaitGroup
	for worker := 0; worker < readerGoroutines; worker++ {
		readers.Add(1)
		go func(worker int) {
			defer readers.Done()
			<-start
			for i := 0; i < requestsPerReader; i++ {
				switch (worker*requestsPerReader + i) % 4 {
				case 0:
					code, header, data := request("/specs")
					var body map[string]any
					if code != http.StatusOK || json.Unmarshal(data, &body) != nil {
						fail("specs code=%d body=%s", code, data)
						continue
					}
					gen, ok := etagGen(header.Get("ETag"))
					if !ok {
						fail("specs bad ETag %q", header.Get("ETag"))
						continue
					}
					want := expectedGeneration(gen)
					if body["report_valid"] != true || body["launch_gate_open"] != want.gateOpen {
						fail("specs gen %d gate = %v, want %v", gen, body["launch_gate_open"], want.gateOpen)
					}
					if body["commit"] != testBuildCommit || body["generated_at"] != want.generatedAt {
						fail("specs gen %d provenance = %v/%v, want %s", gen, body["commit"], body["generated_at"], want.generatedAt)
					}
					alpha := body["specs"].([]any)[0].(map[string]any)
					verdicts, _ := alpha["verdicts"].(map[string]any)
					if got := verdicts["PASS"]; got != float64(want.alphaPass) {
						fail("specs gen %d alpha PASS = %v, want %d", gen, got, want.alphaPass)
					}
					if alpha["indexable"] != want.alphaIndexable {
						fail("specs gen %d alpha indexable = %v, want %v", gen, alpha["indexable"], want.alphaIndexable)
					}
				case 1:
					code, header, data := request("/specs/alpha")
					var body map[string]any
					if code != http.StatusOK || json.Unmarshal(data, &body) != nil {
						fail("spec code=%d body=%s", code, data)
						continue
					}
					gen, ok := etagGen(header.Get("ETag"))
					if !ok {
						fail("spec bad ETag %q", header.Get("ETag"))
						continue
					}
					want := expectedGeneration(gen)
					if body["generated_at"] != want.generatedAt || body["launch_gate_open"] != want.gateOpen {
						fail("spec gen %d mixed: %+v", gen, body)
					}
					for _, row := range body["requirements"].([]any) {
						r := row.(map[string]any)
						if r["id"] == "AL-010" && r["verdict"] != want.al010Verdict {
							fail("spec gen %d AL-010 = %v, want %s", gen, r["verdict"], want.al010Verdict)
						}
					}
				case 2:
					code, header, data := request("/requirements/al-010")
					var body map[string]any
					if code != http.StatusOK || json.Unmarshal(data, &body) != nil {
						fail("requirement code=%d body=%s", code, data)
						continue
					}
					gen, ok := etagGen(header.Get("ETag"))
					if !ok {
						fail("requirement bad ETag %q", header.Get("ETag"))
						continue
					}
					want := expectedGeneration(gen)
					if body["verdict"] != want.al010Verdict || body["commit"] != testBuildCommit ||
						body["generated_at"] != want.generatedAt || body["indexable"] != want.alphaIndexable {
						fail("requirement gen %d mixed: %+v", gen, body)
					}
					if body["source_base_url"] != SourceRepository+"/blob/"+testBuildCommit+"/" {
						fail("requirement gen %d source_base_url = %v", gen, body["source_base_url"])
					}
				case 3:
					code, header, data := request("/sitemap")
					var entries []map[string]any
					if code != http.StatusOK || json.Unmarshal(data, &entries) != nil {
						fail("sitemap code=%d body=%s", code, data)
						continue
					}
					gen, ok := etagGen(header.Get("ETag"))
					if !ok {
						fail("sitemap bad ETag %q", header.Get("ETag"))
						continue
					}
					want := expectedGeneration(gen)
					if len(entries) != want.sitemapLen {
						fail("sitemap gen %d len = %d, want %d", gen, len(entries), want.sitemapLen)
					}
					for _, entry := range entries {
						if entry["lastmod"] != want.generatedAt {
							fail("sitemap gen %d lastmod = %v, want %s", gen, entry["lastmod"], want.generatedAt)
						}
					}
				}
			}
		}(worker)
	}

	close(start)
	writers.Wait()
	readers.Wait()
	for _, message := range failures {
		t.Error(message)
	}
}

type generationExpectation struct {
	generatedAt    string
	gateOpen       bool
	al010Verdict   string
	alphaPass      int
	alphaIndexable any
	sitemapLen     int
}

// expectedGeneration maps an observed generation sequence number to the exact
// snapshot it must represent: activation 1 is report A, reloads then
// alternate B (even ids) and A (odd ids).
func expectedGeneration(gen uint64) generationExpectation {
	if gen == 0 || gen%2 == 1 {
		return generationExpectation{
			generatedAt:    reportAGeneratedAt,
			gateOpen:       true,
			al010Verdict:   "PASS",
			alphaPass:      4,
			alphaIndexable: true,
			sitemapLen:     4,
		}
	}
	return generationExpectation{
		generatedAt:    reportBGeneratedAt,
		gateOpen:       false,
		al010Verdict:   "FAIL",
		alphaPass:      3,
		alphaIndexable: false,
		sitemapLen:     0,
	}
}

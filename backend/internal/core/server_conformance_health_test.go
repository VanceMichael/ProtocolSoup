package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ParleSec/ProtocolSoup/internal/conformance"
	"github.com/ParleSec/ProtocolSoup/internal/plugin"
)

func healthPayload(t *testing.T, server *Server) HealthResponse {
	t.Helper()
	response := httptest.NewRecorder()
	server.handleHealth(response, httptest.NewRequest(http.MethodGet, "/health", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", response.Code)
	}
	var payload HealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	return payload
}

func TestHealthOmitsConformanceWithoutCatalogue(t *testing.T) {
	server := NewServer(&Config{BuildCommit: "deadbeef"}, plugin.NewRegistry(), nil, nil)
	payload := healthPayload(t, server)
	if payload.Conformance != nil {
		t.Fatalf("conformance block = %+v, want omitted without catalogue", payload.Conformance)
	}
}

func TestHealthReportsConformanceGenerationAndReloadError(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")

	registry := conformance.Registry{
		Specifications: []conformance.Specification{
			{ID: "spec", Title: "Spec", ShortTitle: "S 1.0", Version: "1.0", URL: "https://example.test/spec"},
		},
		Requirements: []conformance.Requirement{{
			ID: "R-001", Specification: "spec", Section: "1", Level: "SHOULD", Title: "One",
			Statement: "s", Roles: []string{"holder"}, Applicability: "applicable",
			Implementation: []string{"backend/a.go"},
			Tests:          []conformance.TestRef{{Package: "./a", File: "backend/a_test.go", Name: "TestOne"}},
		}},
	}
	report := conformance.Report{
		SchemaVersion: conformance.SchemaVersion,
		Commit:        "deadbeef",
		GeneratedAt:   "2026-10-01T00:00:00Z",
		Requirements: []conformance.RequirementResult{{
			Requirement: conformance.Requirement{ID: "R-001"},
			Verdict:     conformance.VerdictPass,
		}},
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	catalogue := conformance.NewReloadableCatalogue(registry, reportPath, "deadbeef", nil)
	if outcome := catalogue.Reload(); !outcome.Activated {
		t.Fatalf("initial reload: %v", outcome.Err)
	}
	server := NewServer(&Config{BuildCommit: "deadbeef"}, plugin.NewRegistry(), nil, nil).
		WithConformance(catalogue)

	payload := healthPayload(t, server)
	cf := payload.Conformance
	if cf == nil {
		t.Fatal("conformance block missing")
	}
	if !cf.Configured || cf.ActiveGeneration != 1 || !cf.ReportValid || !cf.LaunchGateOpen {
		t.Fatalf("active health block = %+v", cf)
	}
	if cf.ReportCommit != "deadbeef" || cf.ReportGeneratedAt != "2026-10-01T00:00:00Z" {
		t.Fatalf("provenance = %q/%q", cf.ReportCommit, cf.ReportGeneratedAt)
	}
	if cf.LastReloadAt == "" || cf.LastReloadError != "" {
		t.Fatalf("reload fields = %q/%q, want timestamp with no error", cf.LastReloadAt, cf.LastReloadError)
	}

	// A bad candidate must leave the generation visible at 1 while recording
	// the rejection for operators.
	if err := os.WriteFile(reportPath, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	outcome := catalogue.Reload()
	if outcome.Err == nil || outcome.GenerationID != 1 {
		t.Fatalf("corrupt reload = %+v", outcome)
	}
	cf = healthPayload(t, server).Conformance
	if cf.ActiveGeneration != 1 || cf.ReportValid != true {
		t.Fatalf("health after rejected reload = %+v, want gen 1 retained", cf)
	}
	if cf.LastReloadError == "" || cf.LastReloadErrorAt == "" {
		t.Fatalf("health missing reload error: %+v", cf)
	}

	// Repair activates generation 2 and clears the error.
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if outcome := catalogue.Reload(); !outcome.Activated || outcome.GenerationID != 2 {
		t.Fatalf("recovery reload = %+v", outcome)
	}
	cf = healthPayload(t, server).Conformance
	if cf.ActiveGeneration != 2 || cf.LastReloadError != "" {
		t.Fatalf("health after recovery = %+v, want gen 2 with error cleared", cf)
	}
}

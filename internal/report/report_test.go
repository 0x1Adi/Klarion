package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// rawSecret is the sentinel we assert must never appear in redacted output.
const rawSecret = "AKIAIOSFODNN7EXAMPLE"

// sampleResult builds a Result with two findings: one active real secret and
// one suppressed false positive.
func sampleResult() Result {
	f1 := finding.Finding{
		RuleID:      "aws-access-key",
		Description: "AWS Access Key ID",
		FilePath:    "config/prod.env",
		Line:        12,
		Column:      9,
		EndColumn:   29,
		LineText:    "AWS_KEY=" + rawSecret,
		Secret:      rawSecret,
		Redacted:    finding.Redact(rawSecret),
		Entropy:     0.93,
		EntropyBits: 88.0,
		Severity:    finding.SeverityCritical,
		Context:     "line above\nAWS_KEY=" + rawSecret + "\nline below",
		Verdict:     finding.Verdict{Status: finding.VerdictSecret, Confidence: 0.97, Verifier: "anthropic"},
	}
	f1.Fingerprint = f1.ComputeFingerprint()

	f2 := finding.Finding{
		RuleID:      "generic-api-key",
		Description: "Generic API Key",
		FilePath:    "tests/fixtures.go",
		Line:        3,
		Column:      12,
		EndColumn:   28,
		LineText:    `apiKey := "test1234placeholder"`,
		Secret:      "test1234placeholder",
		Redacted:    finding.Redact("test1234placeholder"),
		Severity:    finding.SeverityMedium,
		Verdict:     finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.9, Verifier: "anthropic"},
		Suppressed:  true,
	}
	f2.Fingerprint = f2.ComputeFingerprint()

	return Result{
		Findings:     []finding.Finding{f1},
		Suppressed:   []finding.Finding{f2},
		FilesScanned: 42,
		Duration:     1500 * time.Millisecond,
		Tool:         "klarion",
		Version:      "1.2.3",
	}
}

func mustRender(t *testing.T, format string, redact, showSuppressed bool) string {
	t.Helper()
	rep, err := New(format, redact, showSuppressed)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	var buf bytes.Buffer
	if err := rep.Write(&buf, sampleResult()); err != nil {
		t.Fatalf("Write(%q): %v", format, err)
	}
	return buf.String()
}

func TestNewUnknownFormat(t *testing.T) {
	if _, err := New("yaml", true, false); err == nil {
		t.Fatal("expected error for unknown format")
	}
	for _, f := range []string{"", "text", "json", "sarif", "junit", "gitlab"} {
		if _, err := New(f, true, false); err != nil {
			t.Errorf("New(%q) unexpected error: %v", f, err)
		}
	}
}

func TestJSONRedaction(t *testing.T) {
	out := mustRender(t, "json", true, true)
	if strings.Contains(out, rawSecret) {
		t.Fatalf("redacted JSON leaked raw secret:\n%s", out)
	}
	if !strings.Contains(out, finding.Redact(rawSecret)) {
		t.Errorf("redacted JSON missing redacted marker %q", finding.Redact(rawSecret))
	}

	// Round-trip: valid JSON with the documented top-level shape.
	var doc jsonReport
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json does not round-trip: %v", err)
	}
	if doc.Tool != "klarion" || doc.Version != "1.2.3" {
		t.Errorf("tool/version wrong: %+v", doc)
	}
	if doc.FilesScanned != 42 || doc.DurationMS != 1500 {
		t.Errorf("files_scanned/duration_ms wrong: %d/%d", doc.FilesScanned, doc.DurationMS)
	}
	if len(doc.Findings) != 1 || len(doc.Suppressed) != 1 {
		t.Fatalf("want 1 finding + 1 suppressed, got %d/%d", len(doc.Findings), len(doc.Suppressed))
	}
	if doc.Summary.Total != 1 || doc.Summary.Suppressed != 1 {
		t.Errorf("summary wrong: %+v", doc.Summary)
	}
	// secret_redacted always present; opt-in "secret" absent under redaction.
	if doc.Findings[0].Redacted == "" {
		t.Error("secret_redacted should be populated")
	}
}

func TestJSONNoRedactIncludesSecret(t *testing.T) {
	out := mustRender(t, "json", false, false)
	if !strings.Contains(out, rawSecret) {
		t.Fatal("no-redact JSON should include raw secret")
	}
	if !strings.Contains(out, `"secret"`) {
		t.Error("no-redact JSON should have a \"secret\" field")
	}
}

func TestSARIF(t *testing.T) {
	out := mustRender(t, "sarif", true, true)
	if strings.Contains(out, rawSecret) {
		t.Fatalf("redacted SARIF leaked raw secret")
	}

	var log sarifLog
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("sarif not valid JSON: %v", err)
	}
	if log.Schema != sarifSchemaURI {
		t.Errorf("schema URI = %q, want %q", log.Schema, sarifSchemaURI)
	}
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("want 1 run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "klarion" {
		t.Errorf("driver name = %q, want klarion", run.Tool.Driver.Name)
	}
	// One result per finding: 1 active + 1 suppressed (showSuppressed=true).
	if len(run.Results) != 2 {
		t.Fatalf("want 2 results, got %d", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("want 2 unique rules, got %d", len(run.Tool.Driver.Rules))
	}

	var active, suppressed *sarifResult
	for i := range run.Results {
		r := &run.Results[i]
		if len(r.Suppressions) > 0 {
			suppressed = r
		} else {
			active = r
		}
	}
	if active == nil || suppressed == nil {
		t.Fatalf("expected one active + one suppressed result")
	}
	if active.Level != "error" { // critical -> error
		t.Errorf("critical finding level = %q, want error", active.Level)
	}
	if suppressed.Level != "warning" { // medium -> warning
		t.Errorf("medium finding level = %q, want warning", suppressed.Level)
	}
	loc := active.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "config/prod.env" || loc.Region.StartLine != 12 || loc.Region.StartColumn != 9 {
		t.Errorf("physical location wrong: %+v", loc)
	}
	if active.PartialFingerprints["klarion/v1"] == "" {
		t.Error("expected partialFingerprints")
	}
}

func TestSARIFHidesSuppressed(t *testing.T) {
	out := mustRender(t, "sarif", true, false)
	var log sarifLog
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	if got := len(log.Runs[0].Results); got != 1 {
		t.Errorf("without showSuppressed want 1 result, got %d", got)
	}
}

func TestJUnit(t *testing.T) {
	out := mustRender(t, "junit", true, true)
	if strings.Contains(out, rawSecret) {
		t.Fatal("redacted junit leaked raw secret")
	}
	var suite junitTestSuite
	if err := xml.Unmarshal([]byte(out), &suite); err != nil {
		t.Fatalf("junit not valid XML: %v", err)
	}
	if suite.Failures != 1 {
		t.Errorf("failures = %d, want 1", suite.Failures)
	}
	if suite.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", suite.Skipped)
	}
	if suite.Tests != 2 {
		t.Errorf("tests = %d, want 2", suite.Tests)
	}
	// Failing case name is rule:file:line.
	var found bool
	for _, tc := range suite.TestCases {
		if tc.Failure != nil && tc.Name == "aws-access-key:config/prod.env:12" {
			found = true
		}
	}
	if !found {
		t.Error("expected failing testcase named rule:file:line")
	}
}

func TestJUnitCleanScan(t *testing.T) {
	rep, _ := New("junit", true, false)
	var buf bytes.Buffer
	if err := rep.Write(&buf, Result{FilesScanned: 5, Tool: "klarion"}); err != nil {
		t.Fatal(err)
	}
	var suite junitTestSuite
	if err := xml.Unmarshal(buf.Bytes(), &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Tests != 1 || suite.Failures != 0 {
		t.Errorf("clean scan want 1 passing testcase, got tests=%d failures=%d", suite.Tests, suite.Failures)
	}
	if suite.TestCases[0].Failure != nil {
		t.Error("clean scan testcase should not fail")
	}
}

func TestGitLab(t *testing.T) {
	out := mustRender(t, "gitlab", true, false)
	if strings.Contains(out, rawSecret) {
		t.Fatal("redacted gitlab leaked raw secret")
	}
	var rep gitlabReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("gitlab not valid JSON: %v", err)
	}
	if rep.Version != "15.0.0" {
		t.Errorf("version = %q, want 15.0.0", rep.Version)
	}
	if len(rep.Vulnerabilities) != 1 {
		t.Fatalf("want 1 vulnerability (suppressed excluded), got %d", len(rep.Vulnerabilities))
	}
	v := rep.Vulnerabilities[0]
	if v.Severity != "Critical" {
		t.Errorf("severity = %q, want Critical", v.Severity)
	}
	if v.Category != "secret_detection" {
		t.Errorf("category = %q, want secret_detection", v.Category)
	}
	if v.Location.File != "config/prod.env" || v.Location.StartLine != 12 {
		t.Errorf("location wrong: %+v", v.Location)
	}
	// id and cve both carry the fingerprint.
	if v.ID == "" || v.CVE != v.ID {
		t.Errorf("expected id==cve==fingerprint, got id=%q cve=%q", v.ID, v.CVE)
	}
	if len(v.Identifiers) == 0 || v.Identifiers[0].Value != "aws-access-key" {
		t.Errorf("identifiers wrong: %+v", v.Identifiers)
	}
}

func TestGitLabSeverityMapping(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.SeverityCritical: "Critical",
		finding.SeverityHigh:     "High",
		finding.SeverityMedium:   "Medium",
		finding.SeverityLow:      "Low",
	}
	for sev, want := range cases {
		if got := gitlabSeverity(sev); got != want {
			t.Errorf("gitlabSeverity(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestText(t *testing.T) {
	out := mustRender(t, "text", true, true)
	if strings.Contains(out, rawSecret) {
		t.Fatalf("redacted text leaked raw secret:\n%s", out)
	}
	if !strings.Contains(out, finding.Redact(rawSecret)) {
		t.Errorf("text missing redacted marker")
	}
	for _, want := range []string{"config/prod.env", "aws-access-key", "critical", "12:9", "secret", "Summary:"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q\n%s", want, out)
		}
	}
	if !strings.Contains(out, "Suppressed:") {
		t.Error("showSuppressed text should have a Suppressed section")
	}
	if !strings.Contains(out, "1 suppressed") {
		t.Error("summary should report suppressed count")
	}
}

func TestTextNoRedactShowsRaw(t *testing.T) {
	out := mustRender(t, "text", false, false)
	if !strings.Contains(out, rawSecret) {
		t.Error("no-redact text should contain raw secret")
	}
}

func TestTextCleanScan(t *testing.T) {
	rep, _ := New("text", true, false)
	var buf bytes.Buffer
	if err := rep.Write(&buf, Result{FilesScanned: 7, Tool: "klarion"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No secrets detected") {
		t.Errorf("clean scan should say no secrets: %s", buf.String())
	}
}

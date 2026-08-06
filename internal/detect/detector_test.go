package detect

// The fixture credentials in this file are synthetic and non-functional, but
// they are deliberately written in real issuer formats — that is the whole
// point of testing a secret detector. Each one is split across a concatenation
// ("ghp_" + "ab12...") so that upstream secret scanners and GitHub push
// protection cannot match them as contiguous text. Go folds the parts at
// compile time, so every assertion still sees the fully assembled string.
// Do not join them back together: doing so makes this repo unpushable.

import (
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

func newDet(t *testing.T) *Detector {
	t.Helper()
	d, err := New(config.Default())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func TestScanContentRuleMatch(t *testing.T) {
	d := newDet(t)
	src := "GITHUB_TOKEN = ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78\n"
	fs := d.ScanContent("app.py", []byte(src))
	if len(fs) == 0 {
		t.Fatal("expected at least one finding")
	}
	var got *finding.Finding
	for i := range fs {
		if fs[i].RuleID == "github-pat" {
			got = &fs[i]
		}
	}
	if got == nil {
		t.Fatalf("github-pat not found; got rules %v", ruleIDs(fs))
	}
	if got.Severity != finding.SeverityCritical {
		t.Errorf("severity = %s, want critical", got.Severity)
	}
	if got.Secret != "ghp_"+"ab12CD34ef56GH78ij90KL12mn34OP56qr78" {
		t.Errorf("secret = %q", got.Secret)
	}
	if strings.Contains(got.Redacted, got.Secret) {
		t.Error("redacted form must not contain the raw secret")
	}
	if got.Line != 1 || got.Column != 16 {
		t.Errorf("location = %d:%d, want 1:16", got.Line, got.Column)
	}
	if got.Fingerprint == "" {
		t.Error("fingerprint not set")
	}
}

func TestScanContentBinarySkipped(t *testing.T) {
	d := newDet(t)
	bin := append([]byte("ghp_"+"ab12CD34ef56GH78ij90KL12mn34OP56qr78"), 0x00, 0x01)
	if fs := d.ScanContent("blob.bin", bin); fs != nil {
		t.Errorf("binary content must not be scanned, got %d findings", len(fs))
	}
}

func TestAllowMarkerSuppresses(t *testing.T) {
	d := newDet(t)
	src := "token = ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78 // klarion:allow\n"
	if fs := d.ScanContent("x", []byte(src)); len(fs) != 0 {
		t.Errorf("line with klarion:allow must be skipped, got %d", len(fs))
	}
}

func TestPlaceholderNotReported(t *testing.T) {
	d := newDet(t)
	// Rule matches the shape but the value screams "example".
	src := "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
	for _, f := range d.ScanContent("x", []byte(src)) {
		if f.RuleID == "aws-access-key-id" {
			t.Error("documented AWS example key must be allowlisted")
		}
	}
}

func TestGenericEntropySweep(t *testing.T) {
	d := newDet(t)
	// A high-entropy token under a non-secret key name: no curated rule matches
	// it, so it must be caught by the Rényi-entropy sweep alone (score ≫ the
	// no-context threshold).
	src := `payload_blob = "kq8vJ2xR7mZp4Wn1cY6tB3dF9gH5sL0aQ"` + "\n"
	fs := d.ScanContent("x", []byte(src))
	found := false
	for _, f := range fs {
		if f.RuleID == "generic-high-entropy" {
			found = true
			if f.Entropy < 0.85 {
				t.Errorf("entropy score = %v, want high", f.Entropy)
			}
		}
	}
	if !found {
		t.Errorf("expected a generic-high-entropy finding; got %v", ruleIDs(fs))
	}
}

func TestGenericEntropyIgnoresProse(t *testing.T) {
	d := newDet(t)
	src := "message = thisisalongsentencemadeentirelyofwords\n"
	for _, f := range d.ScanContent("x", []byte(src)) {
		if f.RuleID == "generic-high-entropy" {
			t.Errorf("prose should not be flagged as high entropy: %q", f.Secret)
		}
	}
}

func TestUUIDNotFlagged(t *testing.T) {
	d := newDet(t)
	src := "id = 550e8400-e29b-41d4-a716-446655440000\n"
	for _, f := range d.ScanContent("x", []byte(src)) {
		if f.RuleID == "generic-high-entropy" {
			t.Error("UUIDs must not be flagged as high-entropy secrets")
		}
	}
}

func TestContextCaptured(t *testing.T) {
	d := newDet(t)
	src := "line1\nline2\ntoken = ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78\nline4\nline5\n"
	fs := d.ScanContent("x", []byte(src))
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	if !strings.Contains(fs[0].Context, "line2") || !strings.Contains(fs[0].Context, "line4") {
		t.Errorf("context should include neighbors, got %q", fs[0].Context)
	}
}

func TestIsBinary(t *testing.T) {
	if !IsBinary([]byte("abc\x00def")) {
		t.Error("NUL byte should mark binary")
	}
	if IsBinary([]byte("plain text\nsecond line")) {
		t.Error("text should not be binary")
	}
}

func TestDisableRule(t *testing.T) {
	cfg := config.Default()
	cfg.Rules.Disable = []string{"github-pat"}
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	src := "ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78\n"
	for _, f := range d.ScanContent("x", []byte(src)) {
		if f.RuleID == "github-pat" {
			t.Error("disabled rule still fired")
		}
	}
}

func ruleIDs(fs []finding.Finding) []string {
	ids := make([]string, len(fs))
	for i, f := range fs {
		ids[i] = f.RuleID
	}
	return ids
}

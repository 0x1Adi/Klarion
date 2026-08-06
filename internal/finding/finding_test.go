package finding

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
)

func TestRedactNeverLeaks(t *testing.T) {
	cases := []string{
		"",
		"abc",
		"ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78",
		"sk_" + "live_51H8xkLDVc0J9mZq3rT7wYpN4bXfA2eKd",
		"short12",
		"exactly16chars!!",
	}
	for _, s := range cases {
		r := Redact(s)
		if s != "" && r == s {
			t.Errorf("Redact(%q) returned the input unchanged", s)
		}
		// The full secret must never appear verbatim in the redaction.
		if len(s) >= 8 && strings.Contains(r, s) {
			t.Errorf("Redact(%q) = %q leaks the whole secret", s, r)
		}
	}
}

func TestRedactShortSecretsHidden(t *testing.T) {
	// Secrets under 8 chars collapse to a fixed mask so their length isn't leaked.
	if Redact("a") != "****" || Redact("abcdef") != "****" {
		t.Error("short secrets must map to a fixed-width mask")
	}
	if Redact("") != "" {
		t.Error("empty secret redacts to empty")
	}
}

func TestRedactInText(t *testing.T) {
	secret := "ghp_" + "ab12CD34ef56GH78ij90KL12mn34OP56qr78"
	line := "token = " + secret + " // committed"
	out := RedactInText(line, secret)
	if strings.Contains(out, secret) {
		t.Fatalf("RedactInText left the raw secret in %q", out)
	}
	if !strings.Contains(out, "token = ") || !strings.Contains(out, "// committed") {
		t.Errorf("RedactInText mangled surrounding text: %q", out)
	}
	if RedactInText("no secret here", "") != "no secret here" {
		t.Error("empty secret should be a no-op")
	}
}

func TestFingerprintStability(t *testing.T) {
	a := Finding{RuleID: "github-pat", FilePath: "app.py", Secret: "ghp_XXXX", Line: 10}
	b := a
	b.Line = 4200 // line drift must not change the fingerprint
	if a.ComputeFingerprint() != b.ComputeFingerprint() {
		t.Error("fingerprint must be stable under line-number drift")
	}
	c := a
	c.Secret = "ghp_YYYY"
	if a.ComputeFingerprint() == c.ComputeFingerprint() {
		t.Error("different secrets must yield different fingerprints")
	}
	d := a
	d.FilePath = "other.py"
	if a.ComputeFingerprint() == d.ComputeFingerprint() {
		t.Error("different paths must yield different fingerprints")
	}
	if len(a.ComputeFingerprint()) != 32 {
		t.Errorf("fingerprint length = %d, want 32", len(a.ComputeFingerprint()))
	}
}

func TestSeverityRankAndParse(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() ||
		SeverityHigh.Rank() <= SeverityMedium.Rank() ||
		SeverityMedium.Rank() <= SeverityLow.Rank() {
		t.Error("severity ranks must be strictly ordered")
	}
	cases := map[string]Severity{
		"CRITICAL": SeverityCritical, "high": SeverityHigh,
		"Medium": SeverityMedium, "low": SeverityLow,
		"garbage": SeverityLow, "": SeverityLow,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

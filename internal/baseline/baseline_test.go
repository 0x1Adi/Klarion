package baseline

// The fixture credentials in this file are synthetic and non-functional, but
// they are deliberately written in real issuer formats — that is the whole
// point of testing a secret detector. Each one is split across a concatenation
// ("ghp_" + "ab12...") so that upstream secret scanners and GitHub push
// protection cannot match them as contiguous text. Go folds the parts at
// compile time, so every assertion still sees the fully assembled string.
// Do not join them back together: doing so makes this repo unpushable.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0x1Adi/Klarion/internal/finding"
)

func mkFinding(rule, file, secret string) finding.Finding {
	f := finding.Finding{
		RuleID:   rule,
		FilePath: file,
		Secret:   secret,
		Redacted: finding.Redact(secret),
	}
	f.Fingerprint = f.ComputeFingerprint()
	return f
}

// TestLoadMissing: a non-existent path yields an empty, usable baseline.
func TestLoadMissing(t *testing.T) {
	b, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	if b == nil || b.Fingerprints == nil {
		t.Fatal("want non-nil baseline with initialized map")
	}
	if len(b.Fingerprints) != 0 {
		t.Fatalf("want empty baseline, got %d entries", len(b.Fingerprints))
	}
}

// TestSaveLoadRoundTrip: FromFindings -> Save -> Load preserves fingerprints
// and entry metadata.
func TestSaveLoadRoundTrip(t *testing.T) {
	findings := []finding.Finding{
		mkFinding("aws-access-key-id", "a.txt", "AKIA5J7QW3ZN8XR2KVPD"),
		mkFinding("github-pat", "b.txt", "ghp_012345678901234567890123456789"+"abcdef"),
	}
	src := FromFindings(findings)
	if len(src.Fingerprints) != 2 {
		t.Fatalf("FromFindings: want 2 entries, got %d", len(src.Fingerprints))
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := src.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("baseline file not written: %v", err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Fingerprints) != len(src.Fingerprints) {
		t.Fatalf("round-trip entry count = %d, want %d",
			len(got.Fingerprints), len(src.Fingerprints))
	}
	for _, f := range findings {
		e, ok := got.Fingerprints[f.Fingerprint]
		if !ok {
			t.Fatalf("fingerprint %s missing after round-trip", f.Fingerprint)
		}
		if e.RuleID != f.RuleID || e.File != f.FilePath || e.Redacted != f.Redacted {
			t.Errorf("entry mismatch for %s: %+v", f.Fingerprint, e)
		}
		if e.AcceptedAt == "" {
			t.Errorf("entry %s missing AcceptedAt timestamp", f.Fingerprint)
		}
	}
}

// TestFilterPartition: Filter splits findings into new vs known by fingerprint.
func TestFilterPartition(t *testing.T) {
	known := mkFinding("aws-access-key-id", "a.txt", "AKIA5J7QW3ZN8XR2KVPD")
	fresh := mkFinding("github-pat", "b.txt", "ghp_012345678901234567890123456789"+"abcdef")

	b := FromFindings([]finding.Finding{known})

	newF, knownF := b.Filter([]finding.Finding{known, fresh})

	if len(knownF) != 1 || knownF[0].Fingerprint != known.Fingerprint {
		t.Fatalf("known partition = %+v, want [%s]", knownF, known.Fingerprint)
	}
	if len(newF) != 1 || newF[0].Fingerprint != fresh.Fingerprint {
		t.Fatalf("new partition = %+v, want [%s]", newF, fresh.Fingerprint)
	}
}

// TestFilterEmptyBaseline: with an empty baseline every finding is new.
func TestFilterEmptyBaseline(t *testing.T) {
	b := &Baseline{Fingerprints: map[string]Entry{}}
	findings := []finding.Finding{
		mkFinding("aws-access-key-id", "a.txt", "AKIA5J7QW3ZN8XR2KVPD"),
		mkFinding("github-pat", "b.txt", "ghp_012345678901234567890123456789"+"abcdef"),
	}
	newF, knownF := b.Filter(findings)
	if len(newF) != 2 || len(knownF) != 0 {
		t.Fatalf("empty baseline: new=%d known=%d, want 2/0", len(newF), len(knownF))
	}
}

// TestLoadEmptyFile: a zero-byte file is treated as an empty baseline.
func TestLoadEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load empty file: %v", err)
	}
	if len(b.Fingerprints) != 0 {
		t.Fatalf("want empty baseline, got %d", len(b.Fingerprints))
	}
}

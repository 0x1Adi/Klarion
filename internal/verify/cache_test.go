package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// TestCacheFlushesDuringScan: a scan killed by a rate limit or a daily token
// quota must keep the verdicts it already paid for. Flushing only at Close
// meant an interrupted run started from zero every time — worst exactly when
// the cache matters most.
func TestCacheFlushesDuringScan(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "verdicts.json")

	c := newCache(&countingVerifier{status: finding.VerdictSecret}, path)

	// Enough candidates to cross the flush window, fed one batch at a time.
	total := flushWindow + 5
	for i := 0; i < total; i++ {
		req := []Request{{Index: 0, Secret: fmt.Sprintf("secret-value-%d", i), FilePath: "f.env"}}
		if _, err := c.Verify(context.Background(), req); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}

	// No Close yet: this is the interrupted-scan case.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ledger was never written mid-scan: %v", err)
	}
	var doc ledger
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("ledger is not valid JSON: %v", err)
	}
	if len(doc.Entries) < flushWindow {
		t.Fatalf("ledger holds %d entries mid-scan, want at least %d", len(doc.Entries), flushWindow)
	}

	// Close still persists the remainder.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	data, _ = os.ReadFile(path)
	_ = json.Unmarshal(data, &doc)
	if len(doc.Entries) != total {
		t.Fatalf("after Close ledger holds %d entries, want %d", len(doc.Entries), total)
	}
}

// countingVerifier answers every request with a fixed status.
type countingVerifier struct{ status finding.VerdictStatus }

func (c *countingVerifier) Name() string { return "counting" }

func (c *countingVerifier) Verify(_ context.Context, batch []Request) ([]finding.Verdict, error) {
	out := make([]finding.Verdict, len(batch))
	for i := range out {
		out[i] = finding.Verdict{Status: c.status, Confidence: 0.9, Verifier: "counting"}
	}
	return out, nil
}

// The cache must never hand one candidate's verdict to a different candidate.
func TestCacheKeySeparatesCandidates(t *testing.T) {
	redact := &config.AIConfig{SendSecret: false, MaxContextLines: 3}
	mk := func(file, secret string, line int, context string) finding.Finding {
		return finding.Finding{RuleID: "generic-password-assignment", FilePath: file, Secret: secret, Line: line, Context: context}
	}
	cases := []struct {
		name   string
		a, b   finding.Finding
		shared bool
	}{
		// send_secret=false sends both as "****"; the old (rule, value) key merged them.
		{"different short values, redacted", mk("app.py", "hunter2", 3, "3: pw = hunter2"), mk("app.py", "Zq9!x7", 3, "3: pw = Zq9!x7"), false},
		{"same value, docs vs prod config", mk("README.md", "hunter2", 3, "3: pw = hunter2"), mk("config/prod.py", "hunter2", 3, "3: pw = hunter2"), false},
		{"same value, different surroundings", mk("app.py", "hunter2", 3, "2: # example\n3: pw = hunter2"), mk("app.py", "hunter2", 3, "2: db = connect()\n3: pw = hunter2"), false},
		{"lines moved by an edit above", mk("app.py", "hunter2", 3, "2: x = 1\n3: pw = hunter2"), mk("app.py", "hunter2", 9, "8: x = 1\n9: pw = hunter2"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := newCache(&fakeVerifier{name: "fake", fn: func(Request) finding.Verdict {
				calls++
				return finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.9}
			}}, "")
			for _, f := range []finding.Finding{tc.a, tc.b} {
				if _, err := c.Verify(context.Background(), []Request{buildRequest(0, &f, redact)}); err != nil {
					t.Fatal(err)
				}
			}
			want := 2
			if tc.shared {
				want = 1
			}
			if calls != want {
				t.Errorf("provider calls = %d, want %d", calls, want)
			}
		})
	}
	// Sanity: the first case really sends identical redacted requests.
	a, b := cases[0].a, cases[0].b
	if ra, rb := buildRequest(0, &a, redact), buildRequest(0, &b, redact); ra.Secret != rb.Secret || ra.Context != rb.Context {
		t.Fatalf("precondition: redacted requests differ (%q vs %q)", ra.Secret, rb.Secret)
	}
}

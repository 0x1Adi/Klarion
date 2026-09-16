package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

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

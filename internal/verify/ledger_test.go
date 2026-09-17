package verify

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// scopedFake lets a test control the cache scope the way a real provider does.
type scopedFake struct {
	*fakeVerifier
	scope string
}

func (s *scopedFake) cacheScope() string { return s.scope }

func newScopedFake(scope string, fn func(Request) finding.Verdict) *scopedFake {
	return &scopedFake{fakeVerifier: &fakeVerifier{name: "fake", fn: fn}, scope: scope}
}

func secretVerdict(r Request) finding.Verdict {
	return finding.Verdict{
		Status:     finding.VerdictFalsePositive,
		Confidence: 0.93,
		// Real providers put the candidate value in the reason; this asserts we
		// never persist it.
		Reason:   "the value " + r.Secret + " is a documented example",
		Verifier: "fake:model-1",
	}
}

// The whole point of the ledger: a second run costs nothing.
func TestLedgerSurvivesAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	batch := []Request{{RuleID: "generic-high-entropy", Secret: "Zk9Qp2Vx7Lm4Rn8Ty1Wc"}}

	calls := 0
	first := newScopedFake("fake:model-1", func(r Request) finding.Verdict {
		calls++
		return secretVerdict(r)
	})
	c1 := newCache(first, path)
	if _, err := c1.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if calls != 1 {
		t.Fatalf("first run made %d provider calls, want 1", calls)
	}

	// Second process: same scope, same candidate — the provider must not be hit.
	second := newScopedFake("fake:model-1", func(r Request) finding.Verdict {
		t.Fatalf("provider called again for %q; the ledger should have answered", r.Secret)
		return finding.Verdict{}
	})
	c2 := newCache(second, path)
	out, err := c2.Verify(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if out[0].Status != finding.VerdictFalsePositive {
		t.Errorf("status = %q, want false_positive to survive the round trip", out[0].Status)
	}
	if out[0].Confidence != 0.93 {
		t.Errorf("confidence = %v, want 0.93", out[0].Confidence)
	}
}

// A ledger lives in the repository being scanned. It must never contain the
// secret, nor the model's prose about it.
func TestLedgerPersistsNoSecretMaterial(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	secret := "Zk9Qp2Vx7Lm4Rn8Ty1Wc"

	c := newCache(newScopedFake("fake:model-1", secretVerdict), path)
	if _, err := c.Verify(context.Background(), []Request{
		{RuleID: "generic-high-entropy", Secret: secret},
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, secret) {
		t.Errorf("ledger contains the raw secret:\n%s", body)
	}
	if strings.Contains(body, "documented example") {
		t.Errorf("ledger contains the model's reason text:\n%s", body)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("ledger mode = %o, want 0600", perm)
	}
}

// Switching model or provider must not inherit the previous judge's verdicts.
func TestLedgerIsScopedToTheModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	batch := []Request{{RuleID: "r", Secret: "candidate-value-123456"}}

	c1 := newCache(newScopedFake("fake:model-1", secretVerdict), path)
	if _, err := c1.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}

	called := false
	c2 := newCache(newScopedFake("fake:model-2", func(r Request) finding.Verdict {
		called = true
		return secretVerdict(r)
	}), path)
	if _, err := c2.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("a different model reused the previous model's verdicts")
	}
}

// "uncertain" is the fallback a provider returns when it could not answer.
// Freezing that into the ledger would make one bad run permanent.
func TestLedgerDoesNotPersistUncertain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	batch := []Request{{RuleID: "r", Secret: "candidate-value-123456"}}

	c := newCache(newScopedFake("fake:model-1", func(r Request) finding.Verdict {
		return finding.Verdict{Status: finding.VerdictUncertain, Reason: noVerdictReason}
	}), path)
	if _, err := c.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		raw, _ := os.ReadFile(path)
		var doc ledger
		_ = json.Unmarshal(raw, &doc)
		if len(doc.Entries) != 0 {
			t.Errorf("uncertain verdict was persisted: %s", raw)
		}
	}
}

// A cache is an optimization. Every way it can be broken must degrade to
// "adjudicate again", never to a failed scan.
func TestLedgerToleratesBadFiles(t *testing.T) {
	batch := []Request{{RuleID: "r", Secret: "candidate-value-123456"}}

	for _, tc := range []struct{ name, content string }{
		{"corrupt json", "{not valid json"},
		{"truncated", `{"version":1,"scope":"fake:model-1","entr`},
		{"future version", `{"version":99,"scope":"fake:model-1","entries":{"x":{"status":"secret"}}}`},
		{"null entries", `{"version":1,"scope":"fake:model-1","entries":null}`},
		{"empty file", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "verdicts.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			called := false
			c := newCache(newScopedFake("fake:model-1", func(r Request) finding.Verdict {
				called = true
				return secretVerdict(r)
			}), path)
			if len(c.entries) != 0 {
				t.Errorf("loaded %d entries from a bad ledger", len(c.entries))
			}
			if _, err := c.Verify(context.Background(), batch); err != nil {
				t.Fatalf("a bad ledger must not fail the scan: %v", err)
			}
			if !called {
				t.Error("provider should have been consulted")
			}
		})
	}
}

// An unwritable path costs the next run money, not this run's result.
func TestLedgerCloseFailureIsNotFatal(t *testing.T) {
	dir := t.TempDir()
	// A path whose parent is a regular file cannot be created.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newCache(newScopedFake("fake:model-1", secretVerdict), filepath.Join(blocker, "verdicts.json"))
	if _, err := c.Verify(context.Background(), []Request{{RuleID: "r", Secret: "abc123def456ghi789"}}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := c.Close(); err == nil {
		t.Error("want an error from an unwritable ledger path")
	}
	// The caller (pipeline.Close) reports and continues; nothing here panics.
}

// With no path configured the cache stays in memory and writes nothing.
func TestLedgerDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	c := newCache(newScopedFake("fake:model-1", secretVerdict), "")
	if _, err := c.Verify(context.Background(), []Request{{RuleID: "r", Secret: "abc123def456ghi789"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close with no path: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("wrote %d file(s) with persistence disabled", len(entries))
	}
}

// A prompt change must not replay the verdicts an older prompt produced.
func TestLedgerIsScopedToThePrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "verdicts.json")
	batch := []Request{{RuleID: "generic-high-entropy", Secret: "Zk9Qp2Vx7Lm4Rn8Ty1Wc"}}

	c1 := newCache(newScopedFake("fake:model-1", secretVerdict), path)
	if _, err := c1.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if err := c1.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc ledger
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if want := "fake:model-1 prompt:" + promptVersion; doc.Scope != want {
		t.Fatalf("scope = %q, want %q", doc.Scope, want)
	}

	// Same model, older prompt.
	doc.Scope = "fake:model-1 prompt:000000000000"
	raw, _ = json.Marshal(doc)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c2 := newCache(newScopedFake("fake:model-1", func(r Request) finding.Verdict {
		calls++
		return secretVerdict(r)
	}), path)
	if _, err := c2.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("provider calls = %d, want 1: a ledger from another prompt was reused", calls)
	}
}

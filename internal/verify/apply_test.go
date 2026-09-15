package verify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// fakeVerifier is an in-memory Verifier used to exercise the orchestration
// logic without any network. It records every batch it receives.
//
// Apply dispatches batches concurrently, so this test double is locked like any
// real Verifier has to be. fn is invoked outside the lock: some tests use it to
// observe overlapping calls, which the lock would serialize away.
type fakeVerifier struct {
	name string
	err  error
	fn   func(Request) finding.Verdict

	mu      sync.Mutex
	batches [][]Request
}

func (f *fakeVerifier) Name() string { return f.name }

func (f *fakeVerifier) Verify(_ context.Context, batch []Request) ([]finding.Verdict, error) {
	f.mu.Lock()
	f.batches = append(f.batches, append([]Request(nil), batch...))
	err := f.err
	f.mu.Unlock()

	if err != nil {
		return nil, err
	}
	out := make([]finding.Verdict, len(batch))
	for i, r := range batch {
		out[i] = f.fn(r)
	}
	return out, nil
}

// batchCount reports how many batches the verifier has seen.
func (f *fakeVerifier) batchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.batches)
}

func mkFindings(secrets ...string) []finding.Finding {
	fs := make([]finding.Finding, len(secrets))
	for i, s := range secrets {
		fs[i] = finding.Finding{RuleID: "generic-high-entropy", Secret: s}
	}
	return fs
}

func TestApplyBatchingAndOrder(t *testing.T) {
	fv := &fakeVerifier{
		name: "fake",
		// Echo the secret into the reason and mark it secret, so we can prove
		// the verdict landed on the right finding.
		fn: func(r Request) finding.Verdict {
			return finding.Verdict{Status: finding.VerdictSecret, Reason: r.Secret, Confidence: 1}
		},
	}
	findings := mkFindings("a", "b", "c", "d", "e")
	// MaxConcurrency 1: this test asserts the *order* batches are cut in, which
	// only has a deterministic answer under serial dispatch. The concurrent
	// path is covered by TestApplyParallelBatchesKeepVerdictsAligned.
	cfg := &config.AIConfig{MaxBatch: 2, MaxConcurrency: 1, OnError: "keep", SendSecret: true}

	if err := Apply(context.Background(), fv, cfg, findings); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	// 5 findings, batch of 2 -> sizes 2, 2, 1.
	wantSizes := []int{2, 2, 1}
	if len(fv.batches) != len(wantSizes) {
		t.Fatalf("got %d batches, want %d", len(fv.batches), len(wantSizes))
	}
	for i, b := range fv.batches {
		if len(b) != wantSizes[i] {
			t.Errorf("batch %d size = %d, want %d", i, len(b), wantSizes[i])
		}
		// Index must reset per batch (0..n-1) so the model can echo it.
		for j, r := range b {
			if r.Index != j {
				t.Errorf("batch %d req %d Index = %d, want %d", i, j, r.Index, j)
			}
		}
	}
	// Order preservation: each finding's verdict reason equals its secret.
	for _, f := range findings {
		if f.Verdict.Reason != f.Secret {
			t.Errorf("finding %q got verdict reason %q (order/mapping mismatch)", f.Secret, f.Verdict.Reason)
		}
		if f.Verdict.Status != finding.VerdictSecret {
			t.Errorf("finding %q status = %q, want secret", f.Secret, f.Verdict.Status)
		}
	}
}

func TestApplyOnErrorKeep(t *testing.T) {
	fv := &fakeVerifier{name: "fake", err: errors.New("boom")}
	findings := mkFindings("a", "b")
	cfg := &config.AIConfig{MaxBatch: 8, OnError: "keep", SendSecret: true}

	if err := Apply(context.Background(), fv, cfg, findings); err != nil {
		t.Fatalf("keep policy should not return error, got %v", err)
	}
	for _, f := range findings {
		// Untouched findings keep their zero-value verdict (unverified state).
		if f.Verdict.Status != "" && f.Verdict.Status != finding.VerdictUnverified {
			t.Errorf("finding %q should remain unverified, got %q", f.Secret, f.Verdict.Status)
		}
	}
}

func TestApplyOnErrorFail(t *testing.T) {
	fv := &fakeVerifier{name: "fake", err: errors.New("boom")}
	findings := mkFindings("a", "b")
	cfg := &config.AIConfig{MaxBatch: 8, OnError: "fail", SendSecret: true}

	if err := Apply(context.Background(), fv, cfg, findings); err == nil {
		t.Fatal("fail policy should return error")
	}
}

func TestApplyRedactsWhenSendSecretFalse(t *testing.T) {
	var seen Request
	fv := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			seen = r
			return finding.Verdict{Status: finding.VerdictUncertain}
		},
	}
	secret := "SuperSecretValue1234567890"
	findings := []finding.Finding{{
		RuleID:  "generic-high-entropy",
		Secret:  secret,
		Context: "token = " + secret + "\nnext line",
	}}
	cfg := &config.AIConfig{MaxBatch: 8, OnError: "keep", SendSecret: false, MaxContextLines: 5}

	if err := Apply(context.Background(), fv, cfg, findings); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if strings.Contains(seen.Secret, secret) {
		t.Errorf("raw secret leaked into request: %q", seen.Secret)
	}
	if seen.Secret != finding.Redact(secret) {
		t.Errorf("secret = %q, want redacted %q", seen.Secret, finding.Redact(secret))
	}
	if strings.Contains(seen.Context, secret) {
		t.Errorf("raw secret leaked into context: %q", seen.Context)
	}
}

func TestApplyCapsContext(t *testing.T) {
	var seen Request
	fv := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			seen = r
			return finding.Verdict{Status: finding.VerdictUncertain}
		},
	}
	findings := []finding.Finding{{
		RuleID:  "generic-high-entropy",
		Secret:  "x",
		Context: "l1\nl2\nl3\nl4\nl5",
	}}
	cfg := &config.AIConfig{MaxBatch: 8, OnError: "keep", SendSecret: true, MaxContextLines: 2}

	if err := Apply(context.Background(), fv, cfg, findings); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := strings.Count(seen.Context, "\n"); got != 1 {
		t.Errorf("context = %q, want 2 lines", seen.Context)
	}
	if seen.Context != "l1\nl2" {
		t.Errorf("context = %q, want %q", seen.Context, "l1\nl2")
	}
}

func TestFilterFalsePositives(t *testing.T) {
	findings := []finding.Finding{
		{Secret: "keep-secret", Verdict: finding.Verdict{Status: finding.VerdictSecret, Confidence: 0.9}},
		{Secret: "drop-fp", Verdict: finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.9}},
		{Secret: "lowconf-fp", Verdict: finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 0.3}},
		{Secret: "uncertain", Verdict: finding.Verdict{Status: finding.VerdictUncertain, Confidence: 0.9}},
	}
	cfg := &config.AIConfig{FilterFalsePositives: true, MinConfidence: 0.6}

	kept, suppressed := FilterFalsePositives(findings, cfg)

	if len(suppressed) != 1 {
		t.Fatalf("suppressed = %d, want 1", len(suppressed))
	}
	if suppressed[0].Secret != "drop-fp" || !suppressed[0].Suppressed {
		t.Errorf("wrong suppressed finding: %+v", suppressed[0])
	}
	if len(kept) != 3 {
		t.Errorf("kept = %d, want 3", len(kept))
	}
	// Low-confidence FP must be kept (below min_confidence).
	found := false
	for _, f := range kept {
		if f.Secret == "lowconf-fp" {
			found = true
		}
	}
	if !found {
		t.Error("low-confidence false positive should be kept")
	}
}

func TestFilterDisabledKeepsAll(t *testing.T) {
	findings := []finding.Finding{
		{Secret: "a", Verdict: finding.Verdict{Status: finding.VerdictFalsePositive, Confidence: 1}},
	}
	cfg := &config.AIConfig{FilterFalsePositives: false, MinConfidence: 0.6}
	kept, suppressed := FilterFalsePositives(findings, cfg)
	if len(kept) != 1 || suppressed != nil {
		t.Errorf("disabled filter should keep all: kept=%d suppressed=%v", len(kept), suppressed)
	}
}

func TestBuildModes(t *testing.T) {
	t.Run("off -> heuristic", func(t *testing.T) {
		v, err := Build(&config.AIConfig{Mode: "off"})
		if err != nil {
			t.Fatal(err)
		}
		if v.Name() != "heuristic" {
			t.Errorf("Name = %q, want heuristic", v.Name())
		}
	})

	t.Run("auto without creds -> heuristic", func(t *testing.T) {
		t.Setenv("KLARION_TEST_KEY", "")
		v, err := Build(&config.AIConfig{Mode: "auto", Provider: "anthropic", APIKeyEnv: "KLARION_TEST_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		if v.Name() != "heuristic" {
			t.Errorf("Name = %q, want heuristic", v.Name())
		}
	})

	t.Run("auto with creds -> cached provider", func(t *testing.T) {
		t.Setenv("KLARION_TEST_KEY", "sk-abc")
		v, err := Build(&config.AIConfig{Mode: "auto", Provider: "anthropic", APIKeyEnv: "KLARION_TEST_KEY"})
		if err != nil {
			t.Fatal(err)
		}
		if v.Name() != "anthropic+cache" {
			t.Errorf("Name = %q, want anthropic+cache", v.Name())
		}
	})

	t.Run("on without creds -> error", func(t *testing.T) {
		t.Setenv("KLARION_TEST_KEY", "")
		if _, err := Build(&config.AIConfig{Mode: "on", Provider: "openai", APIKeyEnv: "KLARION_TEST_KEY"}); err == nil {
			t.Error("expected error for on mode without credentials")
		}
	})

	t.Run("on with ollama needs no key", func(t *testing.T) {
		v, err := Build(&config.AIConfig{Mode: "on", Provider: "ollama"})
		if err != nil {
			t.Fatal(err)
		}
		if v.Name() != "openai+cache" {
			t.Errorf("Name = %q, want openai+cache", v.Name())
		}
	})

	t.Run("unknown mode -> error", func(t *testing.T) {
		if _, err := Build(&config.AIConfig{Mode: "bogus"}); err == nil {
			t.Error("expected error for unknown mode")
		}
	})
}

func TestCacheMemoizes(t *testing.T) {
	calls := 0
	fv := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			calls++
			return finding.Verdict{Status: finding.VerdictSecret, Reason: r.Secret}
		},
	}
	c := newCache(fv, "")
	if c.Name() != "fake+cache" {
		t.Errorf("Name = %q, want fake+cache", c.Name())
	}

	batch := []Request{{RuleID: "r", Secret: "a"}, {RuleID: "r", Secret: "b"}}
	if _, err := c.Verify(context.Background(), batch); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("first pass calls = %d, want 2", calls)
	}
	// Second pass: both cached, inner not called again.
	out, err := c.Verify(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("second pass triggered %d extra inner calls", calls-2)
	}
	if len(fv.batches) != 1 {
		t.Errorf("inner received %d batches, want 1 (second fully cached)", len(fv.batches))
	}
	if out[0].Reason != "a" || out[1].Reason != "b" {
		t.Errorf("cached verdicts out of order: %+v", out)
	}
}

func TestCachePartialMiss(t *testing.T) {
	calls := 0
	fv := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			calls++
			return finding.Verdict{Status: finding.VerdictSecret, Reason: r.Secret}
		},
	}
	c := newCache(fv, "")
	if _, err := c.Verify(context.Background(), []Request{{RuleID: "r", Secret: "a"}}); err != nil {
		t.Fatal(err)
	}
	// "a" cached, "b" is a miss -> only one new inner call.
	out, err := c.Verify(context.Background(), []Request{{RuleID: "r", Secret: "a"}, {RuleID: "r", Secret: "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Errorf("total inner calls = %d, want 2", calls)
	}
	if out[0].Reason != "a" || out[1].Reason != "b" {
		t.Errorf("verdicts mismatched: %+v", out)
	}
}

func TestCacheReindexesMisses(t *testing.T) {
	// A batch where cache hits leave a sparse subset of misses: the inner
	// verifier must receive positional indices (0..n-1), not the requests'
	// original sparse positions — providers map echoed indices positionally.
	fv := &fakeVerifier{
		name: "fake",
		fn: func(r Request) finding.Verdict {
			return finding.Verdict{Status: finding.VerdictSecret, Reason: r.Secret}
		},
	}
	c := newCache(fv, "")
	if _, err := c.Verify(context.Background(), []Request{{Index: 0, RuleID: "r", Secret: "hit"}}); err != nil {
		t.Fatal(err)
	}
	batch := []Request{
		{Index: 0, RuleID: "r", Secret: "hit"},
		{Index: 1, RuleID: "r", Secret: "miss1"},
		{Index: 2, RuleID: "r", Secret: "hit"},
		{Index: 3, RuleID: "r", Secret: "miss2"},
	}
	out, err := c.Verify(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	inner := fv.batches[len(fv.batches)-1]
	if len(inner) != 2 {
		t.Fatalf("inner batch size = %d, want 2 misses", len(inner))
	}
	for i, r := range inner {
		if r.Index != i {
			t.Errorf("inner request %d has Index %d, want positional %d", i, r.Index, i)
		}
	}
	if out[1].Reason != "miss1" || out[3].Reason != "miss2" {
		t.Errorf("miss verdicts misassigned: %+v", out)
	}
}

func TestBuildUserPromptReindexes(t *testing.T) {
	got := buildUserPrompt([]Request{
		{Index: 4, RuleID: "r", Secret: "a"},
		{Index: 9, RuleID: "r", Secret: "b"},
	})
	if !strings.Contains(got, `"index":0`) || !strings.Contains(got, `"index":1`) {
		t.Errorf("prompt should re-index positionally, got: %s", got)
	}
	if strings.Contains(got, `"index":4`) || strings.Contains(got, `"index":9`) {
		t.Errorf("sparse caller indices leaked into prompt: %s", got)
	}
}

// TestDefaultModeRequiresAVerifier guards the decision that a missing key is a
// misconfiguration rather than a reason to fall back.
//
// Klarion is an adjudicator with an entropy pre-filter, not an entropy scanner
// with an optional AI feature: measured across four unseen ecosystems the
// pre-filter alone emits 1,516 findings that adjudication reduces to 316. A
// default of "auto" turned a missing key into a quiet downgrade to that first
// number while the log still read as a successful scan. If this test starts
// failing because the default moved back, that contradiction is back with it.
func TestDefaultModeRequiresAVerifier(t *testing.T) {
	if got := config.Default().AI.Mode; got != "on" {
		t.Fatalf("default ai.mode = %q, want %q", got, "on")
	}

	// Empty Mode must resolve the same way, so a directly-constructed config
	// cannot silently opt out of adjudication.
	for _, mode := range []string{"", "on"} {
		_, err := Build(&config.AIConfig{Mode: mode, Provider: "anthropic", APIKeyEnv: "KLARION_ABSENT_KEY"})
		if err == nil {
			t.Errorf("Build(mode=%q) with no credentials: want error, got nil", mode)
		}
	}

	// The documented escape hatches must still work without credentials.
	for _, mode := range []string{"off", "auto"} {
		if _, err := Build(&config.AIConfig{Mode: mode, Provider: "anthropic", APIKeyEnv: "KLARION_ABSENT_KEY"}); err != nil {
			t.Errorf("Build(mode=%q) with no credentials: want fallback, got %v", mode, err)
		}
	}
}

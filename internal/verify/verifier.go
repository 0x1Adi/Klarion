// Package verify implements Klarion's second stage: AI adjudication of
// candidate findings. A Verifier receives sanitized requests (candidate +
// surrounding code context) and returns a verdict per candidate: real leaked
// secret, false positive, or uncertain.
//
// Providers (anthropic.go, openai.go), the offline heuristic fallback
// (heuristic.go), the verdict cache (cache.go), and the orchestration entry
// point Apply (apply.go) build on the interface defined here.
package verify

import (
	"context"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// Request is one unit of work sent to a Verifier. Context is pre-redacted
// only when the config disables sending raw secrets (ai.send_secret=false);
// otherwise the raw candidate and surrounding lines are included, because the
// model needs them to distinguish a real key from a fixture.
type Request struct {
	Index       int     `json:"index"`
	RuleID      string  `json:"rule_id"`
	Description string  `json:"description"`
	FilePath    string  `json:"file"`
	Line        int     `json:"line"`
	Secret      string  `json:"secret"`
	Context     string  `json:"context"`
	Entropy     float64 `json:"entropy"`

	// Metadata that lets the model decide without reading the repository.
	// Without these it sees five lines of base64 from the middle of a PEM
	// body and can only answer "yes, that is a private key" -- correct, and
	// useless, because it cannot tell a live key from a test fixture.
	IsTestPath  bool   `json:"is_test_path"`
	BlockType   string `json:"block_type"`  // "key_block" | "single_line"
	Occurrences int    `json:"occurrences"` // lines the credential spans
}

// Verifier adjudicates a batch of candidates. Implementations must return
// exactly one Verdict per request, in request order. A returned error means
// the whole batch failed; Apply then follows the configured on_error policy.
//
// Implementations must be safe for concurrent use: Apply dispatches batches to
// several goroutines at once, so any per-verifier state needs its own
// synchronization (see cacheVerifier). The stateless providers satisfy this by
// construction — http.Client is concurrency-safe and the rest is derived from
// immutable config.
type Verifier interface {
	Name() string
	Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error)
}

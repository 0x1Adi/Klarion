package verify

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// cacheVerifier decorates another Verifier, memoizing verdicts keyed by a
// stable hash of the candidate as the model saw it (see cacheKey) so repeated
// candidates cost one provider call rather than several. It is safe for
// concurrent use.
//
// With a path set it also persists across runs, which is what makes CI
// affordable: an unchanged repository re-adjudicates nothing, and a pull
// request only pays for the candidates it actually introduces.
type cacheVerifier struct {
	inner Verifier
	path  string
	label string // provider:model, shown on cached verdicts
	scope string // label plus prompt version: a different model or prompt gets a different cache

	mu      sync.Mutex
	entries map[string]finding.Verdict
	dirty   bool

	// sinceFlush counts verdicts written since the ledger last hit disk.
	sinceFlush int
}

// scopedVerifier is implemented by providers whose verdicts depend on a model.
// The cache is scoped by it so switching models does not silently reuse the old
// model's judgements.
type scopedVerifier interface {
	cacheScope() string
}

// newCache wraps inner. When path is non-empty the ledger at that path is
// loaded (a missing, corrupt, or differently-scoped file simply starts empty —
// a stale cache must never break a scan) and flushed by Close.
func newCache(inner Verifier, path string) *cacheVerifier {
	label := inner.Name()
	if s, ok := inner.(scopedVerifier); ok {
		label = s.cacheScope()
	}
	c := &cacheVerifier{
		inner:   inner,
		path:    path,
		label:   label,
		scope:   label + " prompt:" + promptVersion,
		entries: make(map[string]finding.Verdict),
	}
	if path != "" {
		c.load()
	}
	return c
}

// Name delegates to the inner verifier with a "+cache" suffix so verdict
// provenance stays visible.
func (c *cacheVerifier) Name() string { return c.inner.Name() + "+cache" }

// promptVersion is part of the ledger scope, so verdicts written under an
// older system prompt are discarded instead of replayed.
var promptVersion = func() string {
	sum := sha256.Sum256([]byte(systemPrompt))
	return hex.EncodeToString(sum[:6])
}()

// cacheKey identifies what the model judged: rule, file, value, context,
// related fields, decoded text and span. Context line numbers are stripped, so
// an edit above a candidate keeps its verdict. The key is a one-way hash, so a
// persisted ledger discloses no values.
//
// It used to be (rule, value) alone. A value judged a README example then also
// suppressed the same value in a production config, and with send_secret=false
// every short value under one rule shared a single verdict, because the request
// carries the redacted form ("****"). buildRequest therefore sets the key from
// the raw finding; requests built elsewhere (MCP, tests) hash their own fields.
func cacheKey(r Request) string {
	if r.key != "" {
		return r.key
	}
	return candidateKey(r.RuleID, r.FilePath, r.Secret, r.Context, r.Related, r.Decoded, r.Occurrences)
}

var contextLineNumber = regexp.MustCompile(`(?m)^\d+: `)

func candidateKey(rule, file, secret, context, related, decoded string, occurrences int) string {
	h := sha256.New()
	for _, s := range []string{rule, file, secret, contextLineNumber.ReplaceAllString(context, ""),
		related, decoded, strconv.Itoa(occurrences)} {
		var n [8]byte // length-prefixed, so no field can bleed into the next
		binary.BigEndian.PutUint64(n[:], uint64(len(s)))
		h.Write(n[:])
		h.Write([]byte(s))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Verify returns cached verdicts where available and calls the inner verifier
// only for the misses, preserving request order. On inner error nothing new is
// cached and the error propagates (Apply decides policy).
func (c *cacheVerifier) Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	out := make([]finding.Verdict, len(batch))
	keys := make([]string, len(batch))

	var missReq []Request
	var missIdx []int

	c.mu.Lock()
	for i, r := range batch {
		k := cacheKey(r)
		keys[i] = k
		if v, ok := c.entries[k]; ok {
			out[i] = v
			continue
		}
		// Re-index the miss positionally: providers contractually return one
		// verdict per request in request order, and their index bookkeeping
		// must not be confused by sparse original positions.
		r.Index = len(missReq)
		missReq = append(missReq, r)
		missIdx = append(missIdx, i)
	}
	c.mu.Unlock()

	if len(missReq) == 0 {
		return out, nil
	}

	verdicts, err := c.inner.Verify(ctx, missReq)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	for j, idx := range missIdx {
		if j >= len(verdicts) {
			break
		}
		out[idx] = verdicts[j]
		// An "uncertain" verdict is the safe default the provider falls back to
		// when it could not answer (a dropped result, a truncated response).
		// Persisting that would freeze a non-answer into every future run, so
		// only real judgements are written.
		if verdicts[j].Status != finding.VerdictUncertain {
			c.entries[keys[idx]] = verdicts[j]
			c.dirty = true
			c.sinceFlush++
		}
	}
	if c.sinceFlush >= flushWindow {
		// Losing a cache costs money, not correctness, so a failed flush is
		// never allowed to fail the scan.
		_ = c.flushLocked()
	}
	c.mu.Unlock()

	return out, nil
}

// ledger is the on-disk shape. Only the fields below are persisted — notably
// NOT Verdict.Reason, which is model-authored prose that routinely quotes the
// candidate it describes. Writing that to a file inside the repository being
// scanned would turn the cache into the leak the tool exists to prevent.
type ledger struct {
	Version int                      `json:"version"`
	Scope   string                   `json:"scope"`
	Entries map[string]ledgerVerdict `json:"entries"`
}

type ledgerVerdict struct {
	Status     finding.VerdictStatus `json:"status"`
	Confidence float64               `json:"confidence"`
}

// ledgerVersion 2: keys cover file and context, scope covers the prompt.
const ledgerVersion = 2

// cachedReason marks a verdict that came from the ledger rather than a fresh
// adjudication, so a report never implies the model was consulted this run.
const cachedReason = "verdict reused from a previous run (cached; reasons are not persisted)"

// Close flushes the ledger when persistence is enabled and something changed.
// It is safe to call once at shutdown, and its failure is never fatal: losing a
// cache costs money, not correctness.
func (c *cacheVerifier) Close() error {
	if c.path == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.flushLocked()
}

// flushWindow is how many fresh verdicts may accumulate before the ledger is
// written. Flushing only at Close meant a scan killed by a rate limit, a daily
// token quota or Ctrl-C threw away every verdict it had already paid for --
// which is precisely when the cache is worth the most. Write-then-rename makes
// each flush atomic, so doing it often is safe.
const flushWindow = 25

// flushLocked writes the ledger. The caller must hold c.mu.
func (c *cacheVerifier) flushLocked() error {
	if c.path == "" || !c.dirty {
		return nil
	}

	doc := ledger{
		Version: ledgerVersion,
		Scope:   c.scope,
		Entries: make(map[string]ledgerVerdict, len(c.entries)),
	}
	for k, v := range c.entries {
		doc.Entries[k] = ledgerVerdict{Status: v.Status, Confidence: v.Confidence}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}

	if dir := filepath.Dir(c.path); dir != "" && dir != "." {
		// 0700: the ledger keys off secret fingerprints, so it stays
		// owner-only like the file the rename below lands.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	// Write-then-rename: a scan interrupted mid-flush must not leave a
	// half-written ledger that the next run has to reject.
	tmp, err := os.CreateTemp(filepath.Dir(c.path), ".klarion-cache-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpName, c.path); err != nil {
		return err
	}
	c.dirty = false
	c.sinceFlush = 0
	return nil
}

// load reads a persisted ledger, tolerating every failure mode: a missing file
// (first run), unreadable JSON (truncated by a killed job), a future schema
// version, or entries written by a different provider/model.
func (c *cacheVerifier) load() {
	data, err := os.ReadFile(c.path) // #nosec G304 -- cache path is operator-supplied config, not attacker input
	if err != nil {
		return
	}
	var doc ledger
	if err := json.Unmarshal(data, &doc); err != nil {
		return
	}
	if doc.Version != ledgerVersion || doc.Scope != c.scope || doc.Entries == nil {
		return
	}
	for k, v := range doc.Entries {
		if v.Status == "" || v.Status == finding.VerdictUncertain {
			continue
		}
		c.entries[k] = finding.Verdict{
			Status:     v.Status,
			Confidence: v.Confidence,
			Reason:     cachedReason,
			Verifier:   c.label + "+cache",
		}
	}
}

// Stats reports the ledger size, for `--verbose` output.
func (c *cacheVerifier) Stats() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return fmt.Sprintf("%d cached verdict(s) at %s", len(c.entries), c.path)
}

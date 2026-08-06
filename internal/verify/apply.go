package verify

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// Build constructs the Verifier dictated by cfg. The mode governs the
// safety/availability tradeoff:
//
//   - "off":  offline heuristic only (never calls out).
//   - "auto": use the configured AI provider when credentials are present,
//     otherwise transparently fall back to the heuristic.
//   - "on":   require the AI provider; error out if credentials are missing so
//     a misconfigured "must verify with AI" pipeline fails loudly.
//
// AI providers are wrapped in an (in-memory) verdict cache to collapse repeated
// candidates within a scan.
func Build(cfg *config.AIConfig) (Verifier, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "auto"
	}

	switch mode {
	case "off":
		return newHeuristic(), nil
	case "on":
		if !hasCredentials(cfg) {
			return nil, fmt.Errorf("verify: ai.mode=%q but provider %q is unavailable (%s)",
				cfg.Mode, providerName(cfg), credsHint(cfg))
		}
		return newCache(buildProvider(cfg), cfg.CachePath), nil
	case "auto":
		if hasCredentials(cfg) {
			return newCache(buildProvider(cfg), cfg.CachePath), nil
		}
		return newHeuristic(), nil
	default:
		return nil, fmt.Errorf("verify: unknown ai.mode %q (want off|auto|on)", cfg.Mode)
	}
}

// providerName returns the normalized provider id, defaulting to "anthropic".
func providerName(cfg *config.AIConfig) string {
	p := strings.ToLower(strings.TrimSpace(cfg.Provider))
	if p == "" {
		return "anthropic"
	}
	return p
}

// buildProvider instantiates the concrete provider. "openai" and "ollama"
// share the OpenAI-compatible client (ollama only differs by its default URL,
// applied in config normalization). "claude-cli" shells out to a logged-in
// Claude Code CLI instead of calling an API.
func buildProvider(cfg *config.AIConfig) Verifier {
	switch providerName(cfg) {
	case "openai", "ollama":
		return newOpenAI(cfg)
	case "claude-cli", "claude-code":
		return newClaudeCLI(cfg)
	default:
		return newAnthropic(cfg)
	}
}

// defaultKeyEnv maps a provider to the environment variable that conventionally
// holds its API key. Providers that authenticate out of band (ollama runs
// locally, claude-cli rides an existing CLI login) have no entry.
//
// The mapping is per provider on purpose. A single global default would mean a
// config that names one provider silently authenticates with another vendor's
// key — e.g. `provider = "openai"` posting ANTHROPIC_API_KEY to
// api.openai.com. A scanner must not leak the operator's own credential.
func defaultKeyEnv(provider string) string {
	switch provider {
	case "anthropic":
		return "ANTHROPIC_API_KEY"
	case "openai":
		return "OPENAI_API_KEY"
	}
	return ""
}

// keyEnvName resolves the env var holding the provider's API key. An explicit
// ai.api_key_env always wins; otherwise it is derived from the provider.
func keyEnvName(cfg *config.AIConfig) string {
	if cfg.APIKeyEnv != "" {
		return cfg.APIKeyEnv
	}
	return defaultKeyEnv(providerName(cfg))
}

// apiKey reads the configured provider's key from the environment. An empty
// result means "no key available", which each provider handles per its mode.
func apiKey(cfg *config.AIConfig) string {
	env := keyEnvName(cfg)
	if env == "" {
		return ""
	}
	return os.Getenv(env)
}

// hasCredentials reports whether the configured provider can authenticate.
// Ollama runs locally and needs no key; claude-cli needs the binary on PATH.
func hasCredentials(cfg *config.AIConfig) bool {
	switch providerName(cfg) {
	case "ollama":
		return true
	case "claude-cli", "claude-code":
		return claudeCLIAvailable()
	}
	return apiKey(cfg) != ""
}

// credsHint explains, per provider, what is missing when hasCredentials fails.
func credsHint(cfg *config.AIConfig) string {
	switch providerName(cfg) {
	case "claude-cli", "claude-code":
		return "claude CLI not found on PATH"
	}
	if env := keyEnvName(cfg); env != "" {
		return "set env " + env
	}
	return "no api key environment variable is configured for this provider; set ai.api_key_env"
}

// Apply runs verification over findings, mutating each finding's Verdict in
// place. Requests are sanitized per cfg (secret/context redaction when
// ai.send_secret=false, context capped to ai.max_context_lines) and dispatched
// in batches of ai.max_batch. A batch error follows ai.on_error: "fail" aborts;
// "keep" (the fail-safe default) logs to stderr and leaves that batch's
// findings Unverified so they are still surfaced to the user.
func Apply(ctx context.Context, v Verifier, cfg *config.AIConfig, findings []finding.Finding) error {
	if len(findings) == 0 {
		return nil
	}
	batchSize := cfg.MaxBatch
	if batchSize <= 0 {
		batchSize = 8
	}
	onError := strings.ToLower(strings.TrimSpace(cfg.OnError))
	if onError == "" {
		onError = "keep"
	}

	// Batches are independent: each one owns a disjoint slice of findings and
	// writes only its own verdicts, so they can run concurrently. Sequential
	// dispatch made adjudication latency scale linearly with repository size —
	// a few hundred candidates meant minutes of round-trips in CI.
	type batchRange struct{ start, end int }
	var ranges []batchRange
	for start := 0; start < len(findings); start += batchSize {
		end := start + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		ranges = append(ranges, batchRange{start, end})
	}

	workers := cfg.MaxConcurrency
	if workers <= 0 {
		workers = 4
	}
	if workers > len(ranges) {
		workers = len(ranges)
	}

	// A "fail" policy aborts the whole scan, so cancel the sibling requests as
	// soon as the first batch fails rather than paying for the rest.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu       sync.Mutex
		firstErr error
	)
	work := make(chan batchRange)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range work {
				chunk := findings[r.start:r.end]
				batch := make([]Request, len(chunk))
				for i := range chunk {
					batch[i] = buildRequest(i, &chunk[i], cfg)
				}

				verdicts, err := v.Verify(ctx, batch)
				if err != nil {
					if onError == "fail" {
						mu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("verify: batch [%d:%d] failed: %w", r.start, r.end, err)
							cancel()
						}
						mu.Unlock()
						continue
					}
					// keep: surface the batch as-is, do not block the scan.
					fmt.Fprintf(os.Stderr, "klarion: verification failed for findings [%d:%d], keeping them unverified: %v\n", r.start, r.end, err)
					continue
				}
				for i := range chunk {
					if i < len(verdicts) {
						chunk[i].Verdict = verdicts[i]
					}
				}
			}
		}()
	}

	for _, r := range ranges {
		select {
		case work <- r:
		case <-ctx.Done():
		}
	}
	close(work)
	wg.Wait()

	return firstErr
}

// buildRequest sanitizes one finding into a verifier Request. index is the
// candidate's position within its batch (the id the model echoes back).
func buildRequest(index int, f *finding.Finding, cfg *config.AIConfig) Request {
	secret := f.Secret
	ctxText := capContext(f.Context, cfg.MaxContextLines, f.Line)
	if !cfg.SendSecret {
		// Strict privacy: never let the raw value leave the process.
		ctxText = finding.RedactInText(ctxText, f.Secret)
		secret = finding.Redact(f.Secret)
	}
	return Request{
		Index:       index,
		RuleID:      f.RuleID,
		Description: f.Description,
		FilePath:    f.FilePath,
		Line:        f.Line,
		Secret:      secret,
		Context:     ctxText,
		Entropy:     f.Entropy,
	}
}

// capContext truncates the context to at most n lines (0 or negative = no cap),
// keeping the window centered on the line the candidate was found on.
//
// Taking a plain head slice here used to drop the matched line entirely: the
// detector emits contextRadius lines either side of the match, so with the
// default radius 3 and cap 3 the request carried only the three *preceding*
// lines and never the code containing the secret. Centering keeps the decisive
// line in every request, for both the offline heuristics and the LLM verifier.
func capContext(s string, n, matchLine int) string {
	if n <= 0 || s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}

	// Locate the matched line by its "<line number>: " prefix.
	idx := -1
	prefix := fmt.Sprintf("%d: ", matchLine)
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			idx = i
			break
		}
	}
	if idx < 0 {
		return strings.Join(lines[:n], "\n") // unknown: preserve old behaviour
	}

	// Center the window on idx, clamping at both ends.
	lo := idx - n/2
	if lo < 0 {
		lo = 0
	}
	hi := lo + n
	if hi > len(lines) {
		hi = len(lines)
		lo = hi - n
	}
	return strings.Join(lines[lo:hi], "\n")
}

// FilterFalsePositives partitions findings after verification. When
// ai.filter_false_positives is enabled, findings judged false_positive with
// confidence ≥ ai.min_confidence are marked Suppressed and moved to the
// suppressed slice; everything else is kept. When disabled, all are kept.
func FilterFalsePositives(findings []finding.Finding, cfg *config.AIConfig) (kept, suppressed []finding.Finding) {
	if !cfg.FilterFalsePositives {
		return findings, nil
	}
	for _, f := range findings {
		if f.Verdict.Status == finding.VerdictFalsePositive && f.Verdict.Confidence >= cfg.MinConfidence {
			f.Suppressed = true
			suppressed = append(suppressed, f)
			continue
		}
		kept = append(kept, f)
	}
	return kept, suppressed
}

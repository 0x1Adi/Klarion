package verify

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// defaultClaudeCLIModel is the alias passed to `claude --model`. Haiku keeps
// adjudication fast and cheap; any alias or full model id the CLI accepts
// works here.
const defaultClaudeCLIModel = "haiku"

// claudeCLIBinary is the executable resolved from PATH. A var so tests can
// point it at a stub.
var claudeCLIBinary = "claude"

// claudeCLIVerifier adjudicates candidates by shelling out to the Claude Code
// CLI in print mode (`claude -p`). It exists for environments that have an
// authenticated Claude Code subscription but no raw API key: same system
// prompt, same output contract as the API providers, different transport.
type claudeCLIVerifier struct {
	model   string
	timeout time.Duration
}

func newClaudeCLI(cfg *config.AIConfig) *claudeCLIVerifier {
	model := cfg.Model
	// The config default targets the Anthropic API; map it to the CLI alias.
	if model == "" || model == defaultAnthropicModel {
		model = defaultClaudeCLIModel
	}
	to := time.Duration(cfg.TimeoutSecs) * time.Second
	if to <= 0 {
		// CLI startup + a full batch is slower than a raw API call; give it
		// more headroom than the API providers' 45s default.
		to = 120 * time.Second
	}
	return &claudeCLIVerifier{model: model, timeout: to}
}

// Name identifies this verifier in logs and verdicts.
func (c *claudeCLIVerifier) Name() string { return "claude-cli" }

// cacheScope keys the persistent verdict cache (see anthropicVerifier).
func (c *claudeCLIVerifier) cacheScope() string { return "claude-cli:" + c.model }

// cliRetries is how many times a failed CLI invocation is reattempted. The
// CLI is a spawned process talking to a shared login session, so transient
// nonzero exits (rate limits, session contention) are expected occasionally;
// one retry keeps long on_error=fail scans from dying to a single blip.
const cliRetries = 2

// cliRetryDelay is the base backoff between attempts (attempt N waits N of
// these). A var so tests can zero it.
var cliRetryDelay = 5 * time.Second

// Verify classifies the batch via non-interactive CLI invocations. The model
// occasionally returns fewer result objects than candidates; unresolved
// candidates are re-queried in follow-up calls (refill) instead of silently
// defaulting to uncertain, so every verdict reflects an actual judgement
// whenever the CLI cooperates.
func (c *claudeCLIVerifier) Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	verdicts := make([]finding.Verdict, len(batch))
	resolved := make([]bool, len(batch))
	pendingIdx := make([]int, len(batch))
	for i := range batch {
		pendingIdx[i] = i
	}
	var lastErr error

	for attempt := 0; attempt <= cliRetries && len(pendingIdx) > 0; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * cliRetryDelay):
			}
		}
		// The pending subset is tracked by position in the original batch;
		// buildUserPrompt re-indexes what the model sees, and verifyOnce
		// returns verdicts in subset order.
		sub := make([]Request, len(pendingIdx))
		for i, oi := range pendingIdx {
			sub[i] = batch[oi]
		}

		got, err := c.verifyOnce(ctx, sub)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		var still []int
		for i, v := range got {
			oi := pendingIdx[i]
			if v.Reason == noVerdictReason {
				still = append(still, oi)
				continue
			}
			verdicts[oi] = v
			resolved[oi] = true
		}
		pendingIdx = still
	}

	if lastErr != nil && !anyResolved(resolved) {
		// Every attempt failed outright: surface the error so Apply can obey
		// the configured on_error policy.
		return nil, lastErr
	}
	for i := range verdicts {
		if !resolved[i] {
			verdicts[i] = finding.Verdict{
				Status:   finding.VerdictUncertain,
				Reason:   noVerdictReason,
				Verifier: "claude-cli:" + c.model,
			}
		}
	}
	return verdicts, nil
}

func anyResolved(resolved []bool) bool {
	for _, r := range resolved {
		if r {
			return true
		}
	}
	return false
}

func (c *claudeCLIVerifier) verifyOnce(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// #nosec G204 -- fixed binary, argv slice (no shell); the model name is
	// operator config and the prompt is delivered on stdin, not as an arg.
	cmd := exec.CommandContext(ctx, claudeCLIBinary,
		"-p",
		"--model", c.model,
		"--system-prompt", systemPrompt,
		// The payload is self-contained, so the verifier needs no tools.
		// Left enabled, `claude -p` runs a full agent loop: it re-reads files
		// and shells out (keytool, rg) before ruling. That is many turns per
		// candidate, makes verdicts non-deterministic, and hands an agent
		// Bash access to the untrusted checkout being scanned.
		"--disallowedTools", "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,Task,TodoWrite,NotebookEdit",
	)
	cmd.Stdin = strings.NewReader(buildUserPrompt(batch))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("claude-cli: %s", msg)
	}

	br, err := parseBatchResults(stdout.String())
	if err != nil {
		return nil, fmt.Errorf("claude-cli: %w", err)
	}
	return mapResults(batch, br, "claude-cli:"+c.model), nil
}

// claudeCLIAvailable reports whether the CLI binary is on PATH; it is the
// claude-cli provider's equivalent of "credentials are present".
func claudeCLIAvailable() bool {
	_, err := exec.LookPath(claudeCLIBinary)
	return err == nil
}

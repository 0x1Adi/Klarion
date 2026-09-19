package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// commandVerifier adjudicates candidates by running an operator-supplied
// program. The batch goes to its stdin as a JSON array of Request (indices
// rewritten 0..n-1); stdout must carry the same {"results":[...]} object the
// model providers return. No key, no network: the judge is whatever the
// operator configured, e.g. a local classifier.
type commandVerifier struct {
	argv    []string
	timeout time.Duration
}

func newCommand(cfg *config.AIConfig) *commandVerifier {
	to := time.Duration(cfg.TimeoutSecs) * time.Second
	if to <= 0 {
		to = 120 * time.Second
	}
	return &commandVerifier{argv: strings.Fields(cfg.Command), timeout: to}
}

func (c *commandVerifier) Name() string { return "command" }

func (c *commandVerifier) cacheScope() string { return "command:" + strings.Join(c.argv, " ") }

func (c *commandVerifier) Verify(ctx context.Context, batch []Request) ([]finding.Verdict, error) {
	if len(batch) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	prompt := make([]Request, len(batch))
	for i, r := range batch {
		r.Index = i
		prompt[i] = r
	}
	// #nosec G117 -- the candidate secret is the payload: judging it is the
	// point, and it goes only to the stdin of the command the operator configured.
	body, _ := json.Marshal(prompt)

	// #nosec G204 -- argv is operator config, no shell; the batch travels on stdin.
	cmd := exec.CommandContext(ctx, c.argv[0], c.argv[1:]...)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("command: %s", msg)
	}
	br, err := parseBatchResults(stdout.String())
	if err != nil {
		return nil, fmt.Errorf("command: %w", err)
	}
	return mapResults(batch, br, c.cacheScope()), nil
}

// commandAvailable reports whether ai.command names a resolvable executable.
func commandAvailable(cfg *config.AIConfig) bool {
	argv := strings.Fields(cfg.Command)
	if len(argv) == 0 {
		return false
	}
	_, err := exec.LookPath(argv[0])
	return err == nil
}

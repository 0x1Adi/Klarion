package verify

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// stubClaude writes a fake `claude` executable that emits canned stdout and
// points claudeCLIBinary at it for the duration of the test.
func stubClaude(t *testing.T, stdout string, exitCode int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "claude")
	script := "#!/bin/sh\ncat > /dev/null\nprintf '%s' " + shellQuote(stdout) + "\nexit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := claudeCLIBinary
	claudeCLIBinary = path
	t.Cleanup(func() { claudeCLIBinary = old })
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// stubClaudeSequence installs a fake `claude` that returns outputs[i] on its
// i-th invocation (repeating the last output when exhausted).
func stubClaudeSequence(t *testing.T, outputs []string) {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("#!/bin/sh\ncat > /dev/null\nC=$(cat \"" + dir + "/count\" 2>/dev/null || echo 0)\necho $((C+1)) > \"" + dir + "/count\"\ncase $C in\n")
	for i, out := range outputs {
		if i == len(outputs)-1 {
			b.WriteString("*) printf '%s' " + shellQuote(out) + ";;\n")
		} else {
			b.WriteString(strconv.Itoa(i) + ") printf '%s' " + shellQuote(out) + ";;\n")
		}
	}
	b.WriteString("esac\n")
	path := filepath.Join(dir, "claude")
	if err := os.WriteFile(path, []byte(b.String()), 0o755); err != nil {
		t.Fatal(err)
	}
	old := claudeCLIBinary
	claudeCLIBinary = path
	t.Cleanup(func() { claudeCLIBinary = old })
}

func cliTestBatch() []Request {
	return []Request{
		{Index: 0, RuleID: "aws-access-key-id", Secret: "AKIAIOSFODNN7EXAMPLE"},
		{Index: 1, RuleID: "generic-high-entropy", Secret: "not-really-random"},
	}
}

func TestClaudeCLIVerifyParsesFencedJSON(t *testing.T) {
	stubClaude(t, "```json\n{\"results\":[{\"index\":0,\"status\":\"secret\",\"confidence\":0.9,\"reason\":\"aws key\"},{\"index\":1,\"status\":\"false_positive\",\"confidence\":0.8,\"reason\":\"placeholder\"}]}\n```", 0)

	v := newClaudeCLI(&config.AIConfig{})
	verdicts, err := v.Verify(context.Background(), cliTestBatch())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(verdicts) != 2 {
		t.Fatalf("want 2 verdicts, got %d", len(verdicts))
	}
	if verdicts[0].Status != finding.VerdictSecret || verdicts[1].Status != finding.VerdictFalsePositive {
		t.Fatalf("unexpected statuses: %+v", verdicts)
	}
	if verdicts[0].Verifier != "claude-cli:"+defaultClaudeCLIModel {
		t.Fatalf("unexpected verifier name: %q", verdicts[0].Verifier)
	}
}

func TestClaudeCLIVerifyMissingIndexDefaultsUncertain(t *testing.T) {
	// Index 1 is never returned, even by refill calls: it must fall back to
	// the safe default while index 0's real verdict survives.
	stubClaudeSequence(t, []string{
		`{"results":[{"index":0,"status":"secret","confidence":1,"reason":"k"}]}`,
		`{"results":[]}`,
	})
	oldDelay := cliRetryDelay
	cliRetryDelay = 0
	t.Cleanup(func() { cliRetryDelay = oldDelay })

	v := newClaudeCLI(&config.AIConfig{})
	verdicts, err := v.Verify(context.Background(), cliTestBatch())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdicts[0].Status != finding.VerdictSecret {
		t.Fatalf("resolved verdict lost: %+v", verdicts[0])
	}
	// The stub never returns index 1, so after refill attempts it must fall
	// back to the safe default.
	if verdicts[1].Status != finding.VerdictUncertain || verdicts[1].Reason != noVerdictReason {
		t.Fatalf("missing verdict should default to uncertain, got %+v", verdicts[1])
	}
}

func TestClaudeCLIVerifyRefillsMissingVerdicts(t *testing.T) {
	// First call: verdict for index 0 only. Refill call: the single pending
	// candidate (re-indexed to 0) gets a verdict. Both slots end up resolved.
	stubClaudeSequence(t, []string{
		`{"results":[{"index":0,"status":"secret","confidence":0.9,"reason":"real"}]}`,
		`{"results":[{"index":0,"status":"false_positive","confidence":0.8,"reason":"placeholder"}]}`,
	})
	oldDelay := cliRetryDelay
	cliRetryDelay = 0
	t.Cleanup(func() { cliRetryDelay = oldDelay })

	v := newClaudeCLI(&config.AIConfig{})
	verdicts, err := v.Verify(context.Background(), cliTestBatch())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdicts[0].Status != finding.VerdictSecret {
		t.Fatalf("verdict 0: %+v", verdicts[0])
	}
	if verdicts[1].Status != finding.VerdictFalsePositive {
		t.Fatalf("refilled verdict 1 should be false_positive, got %+v", verdicts[1])
	}
}

func TestClaudeCLIVerifyCommandFailure(t *testing.T) {
	stubClaude(t, "", 1)
	oldDelay := cliRetryDelay
	cliRetryDelay = 0
	t.Cleanup(func() { cliRetryDelay = oldDelay })

	v := newClaudeCLI(&config.AIConfig{})
	if _, err := v.Verify(context.Background(), cliTestBatch()); err == nil {
		t.Fatal("want error when the CLI exits nonzero")
	}
}

func TestBuildClaudeCLIProvider(t *testing.T) {
	stubClaude(t, "{}", 0)

	v, err := Build(&config.AIConfig{Mode: "on", Provider: "claude-cli"})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// The provider is wrapped in the verdict cache; the underlying name must
	// surface through it.
	if got := v.Name(); !strings.Contains(got, "claude-cli") {
		t.Fatalf("Build returned %q, want a claude-cli verifier", got)
	}
}

func TestBuildClaudeCLIMissingBinary(t *testing.T) {
	old := claudeCLIBinary
	claudeCLIBinary = "klarion-test-no-such-binary"
	t.Cleanup(func() { claudeCLIBinary = old })

	if _, err := Build(&config.AIConfig{Mode: "on", Provider: "claude-cli"}); err == nil {
		t.Fatal("want error when claude binary is missing and mode=on")
	}
}

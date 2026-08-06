package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The hook is the gate that stands between an AI agent and a leaked credential,
// and it is fail-open by design — which means a silent bug here does not break
// anything visibly, it just stops protecting. These tests pin the decision for
// each shape of input.

// runHookWith drives runHook against a payload with a config in a temp dir,
// returning the decision envelope.
func runHookWith(t *testing.T, payload any, configTOML string) hookSpecific {
	t.Helper()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".klarion.toml")
	if err := os.WriteFile(cfgPath, []byte(configTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	// loadConfig reads --config first; set it for the duration of the test.
	prev := flagConfig
	flagConfig = cfgPath
	t.Cleanup(func() { flagConfig = prev })

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := runHook(context.Background(), bytes.NewReader(raw), &out); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	var env preToolUseOutput
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatalf("decode decision %q: %v", out.String(), err)
	}
	return env.HookSpecificOutput
}

// noAI keeps the hook on the offline heuristic so tests never touch a network.
const noAI = "[ai]\nmode = \"off\"\n"

// A live AWS key is unambiguous — the tool call must be denied.
func TestHookDeniesRealSecret(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Write",
		"tool_input": map[string]any{
			"file_path": "deploy/config.py",
			"content":   "AWS_SECRET_ACCESS_KEY = \"" + "wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYzEXAMPLE1\"\naws_access_key_id = \"AKIA" + "Z7QW3MPLXV2KRT8N\"\n",
		},
	}, noAI)

	if got.PermissionDecision != "deny" {
		t.Fatalf("decision = %q, want deny (reason: %s)", got.PermissionDecision, got.PermissionDecisionReason)
	}
	if !strings.Contains(got.PermissionDecisionReason, "Klarion blocked") {
		t.Errorf("reason should explain the block, got %q", got.PermissionDecisionReason)
	}
}

// The reason is fed back to the agent, so it must never contain the raw value.
func TestHookReasonDoesNotLeakSecret(t *testing.T) {
	secret := "AKIA" + "Z7QW3MPLXV2KRT8N"
	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.py", "content": "key = \"" + secret + "\""},
	}, noAI)

	if got.PermissionDecision != "deny" {
		t.Fatalf("decision = %q, want deny", got.PermissionDecision)
	}
	if strings.Contains(got.PermissionDecisionReason, secret) {
		t.Errorf("raw secret echoed back to the agent: %q", got.PermissionDecisionReason)
	}
}

func TestHookAllowsCleanContent(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "main.go", "content": "package main\n\nfunc main() {}\n"},
	}, noAI)

	if got.PermissionDecision != "allow" {
		t.Errorf("decision = %q, want allow (reason: %s)", got.PermissionDecision, got.PermissionDecisionReason)
	}
}

// Secrets pasted inline into a shell command are scanned too.
func TestHookScansBashCommands(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": "curl -H 'x-key: AKIA" + "Z7QW3MPLXV2KRT8N' https://example.com"},
	}, noAI)

	if got.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny for a secret in a Bash command", got.PermissionDecision)
	}
}

// Edit and MultiEdit carry their content in different fields; both must be read.
func TestHookScansEditShapes(t *testing.T) {
	secret := "AKIA" + "Z7QW3MPLXV2KRT8N"

	t.Run("Edit new_string", func(t *testing.T) {
		got := runHookWith(t, map[string]any{
			"tool_name":  "Edit",
			"tool_input": map[string]any{"file_path": "a.py", "new_string": "key = \"" + secret + "\""},
		}, noAI)
		if got.PermissionDecision != "deny" {
			t.Errorf("decision = %q, want deny", got.PermissionDecision)
		}
	})

	t.Run("MultiEdit edits", func(t *testing.T) {
		got := runHookWith(t, map[string]any{
			"tool_name": "MultiEdit",
			"tool_input": map[string]any{
				"file_path": "a.py",
				"edits": []map[string]string{
					{"new_string": "harmless = 1"},
					{"new_string": "key = \"" + secret + "\""},
				},
			},
		}, noAI)
		if got.PermissionDecision != "deny" {
			t.Errorf("decision = %q, want deny", got.PermissionDecision)
		}
	})
}

// [hook] decision = "ask" downgrades the block to a prompt rather than a denial.
func TestHookDecisionAsk(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.py", "content": "key = \"AKIA" + "Z7QW3MPLXV2KRT8N\""},
	}, noAI+"[hook]\ndecision = \"ask\"\n")

	if got.PermissionDecision != "ask" {
		t.Errorf("decision = %q, want ask", got.PermissionDecision)
	}
}

// Malformed input must not wedge the agent: fail open by default.
func TestHookFailsOpenOnGarbageInput(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".klarion.toml")
	if err := os.WriteFile(cfgPath, []byte(noAI), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := flagConfig
	flagConfig = cfgPath
	t.Cleanup(func() { flagConfig = prev })

	var out bytes.Buffer
	if err := runHook(context.Background(), strings.NewReader("{not json"), &out); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	var env preToolUseOutput
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("decision = %q, want allow (fail-open)", env.HookSpecificOutput.PermissionDecision)
	}
}

// fail_open = false is the opt-out: an operator who would rather block than
// risk missing a secret gets a denial when the scanner cannot do its job.
func TestHookFailClosedWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".klarion.toml")
	if err := os.WriteFile(cfgPath, []byte(noAI+"[hook]\nfail_open = false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := flagConfig
	flagConfig = cfgPath
	t.Cleanup(func() { flagConfig = prev })

	var out bytes.Buffer
	if err := runHook(context.Background(), strings.NewReader("{not json"), &out); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	var env preToolUseOutput
	if err := json.Unmarshal(out.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if env.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny when fail_open = false", env.HookSpecificOutput.PermissionDecision)
	}
}

// block_on raises the severity floor; a medium finding must not trip a
// high-only gate.
func TestHookRespectsBlockOnSeverity(t *testing.T) {
	// A JWT is classified medium by the built-in ruleset.
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	payload := map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.py", "content": "token = \"" + jwt + "\""},
	}

	if got := runHookWith(t, payload, noAI); got.PermissionDecision != "deny" {
		t.Errorf("block_on=low: decision = %q, want deny", got.PermissionDecision)
	}
	if got := runHookWith(t, payload, noAI+"[hook]\nblock_on = \"critical\"\n"); got.PermissionDecision != "allow" {
		t.Errorf("block_on=critical: decision = %q, want allow for a medium finding", got.PermissionDecision)
	}
}

// An empty payload has nothing to scan and must not block.
func TestHookAllowsEmptyPayload(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.py", "content": ""},
	}, noAI)

	if got.PermissionDecision != "allow" {
		t.Errorf("decision = %q, want allow", got.PermissionDecision)
	}
}

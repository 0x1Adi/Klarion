package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The hook is the gate that stands between an AI agent and a leaked credential,
// and it is fail-open by design — which means a silent bug here does not break
// anything visibly, it just stops protecting. These tests pin the decision for
// each shape of input.

// hookResult is what the hook printed: a decision (empty when it made none), a
// note, and the raw output.
type hookResult struct {
	hookSpecific
	SystemMessage string
	Raw           string
}

// decodeHook parses the hook's output. No output means no decision.
func decodeHook(t *testing.T, out []byte) hookResult {
	t.Helper()
	res := hookResult{Raw: string(out)}
	if len(bytes.TrimSpace(out)) == 0 {
		return res
	}
	var env preToolUseOutput
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("decode hook output %q: %v", out, err)
	}
	if env.HookSpecificOutput != nil {
		res.hookSpecific = *env.HookSpecificOutput
	}
	res.SystemMessage = env.SystemMessage
	return res
}

// runHookWith drives runHook against a payload with a config in a temp dir,
// returning what the hook printed.
func runHookWith(t *testing.T, payload any, configTOML string) hookResult {
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
	return decodeHook(t, out.Bytes())
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

	if got.Raw != "" {
		t.Errorf("clean content: hook printed %q, want nothing", got.Raw)
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
	got := decodeHook(t, out.Bytes())
	if got.PermissionDecision != "" {
		t.Errorf("decision = %q, want none (fail-open)", got.PermissionDecision)
	}
	// The user must be able to see that nothing was scanned.
	if !strings.Contains(got.SystemMessage, "did not scan") {
		t.Errorf("fail-open note should say it did not scan, got %q", got.SystemMessage)
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
	if got := decodeHook(t, out.Bytes()); got.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny when fail_open = false", got.PermissionDecision)
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
	if got := runHookWith(t, payload, noAI+"[hook]\nblock_on = \"critical\"\n"); got.PermissionDecision != "" {
		t.Errorf("block_on=critical: decision = %q, want none for a medium finding", got.PermissionDecision)
	}
}

// An empty payload has nothing to scan and must not block.
func TestHookAllowsEmptyPayload(t *testing.T) {
	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "a.py", "content": ""},
	}, noAI)

	if got.Raw != "" {
		t.Errorf("empty payload: hook printed %q, want nothing", got.Raw)
	}
}

// Claude Code sends absolute paths. A parent directory named like a test tree
// ("examples", "test") must not turn every file in the project into a fixture.
func TestHookJudgesPathInsideProject(t *testing.T) {
	root := filepath.Join(t.TempDir(), "examples", "shop")
	payload := func(cwd string) map[string]any {
		return map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "Write",
			"cwd":             cwd,
			"tool_input": map[string]any{
				"file_path": filepath.Join(root, "src", "settings.py"),
				"content":   "api_token = \"" + "Zk9Qp2Vx7Lm4" + "Rn8Ty1WcQe3\"\n",
			},
		}
	}
	if got := runHookWith(t, payload(root), noAI); got.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny: src/settings.py is not a test file", got.PermissionDecision)
	}
	// Sanity: judged by the absolute path, the parent "examples" dir hides it.
	if got := runHookWith(t, payload(""), noAI); got.PermissionDecision != "" {
		t.Fatalf("precondition: absolute path decision = %q, want none", got.PermissionDecision)
	}
}

// With no AI provider the hook still blocks provider keys, and only those, so
// an unconfigured install neither protects nothing nor blocks ordinary code.
func TestHookOfflineBlocksProviderCredentialsOnly(t *testing.T) {
	t.Setenv("KLARION_TEST_ABSENT_KEY", "")
	cfg := "[ai]\nmode = \"on\"\nprovider = \"openai\"\napi_key_env = \"KLARION_TEST_ABSENT_KEY\"\n"
	write := func(content string) map[string]any {
		return map[string]any{
			"tool_name":  "Write",
			"tool_input": map[string]any{"file_path": "app/config.py", "content": content},
		}
	}
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	cases := []struct {
		name, content, want string
	}{
		{"AWS key", "aws_access_key_id = \"AKIA" + "Z7QW3MPLXV2KRT8N\"\n", "deny"},
		{"JWT", "token = \"" + jwt + "\"\n", ""},
		{"generic assignment", "api_token = \"" + "Zk9Qp2Vx7Lm4" + "Rn8Ty1WcQe3\"\n", ""},
	}
	for _, tc := range cases {
		if got := runHookWith(t, write(tc.content), cfg); got.PermissionDecision != tc.want {
			t.Errorf("%s: decision = %q, want %s (reason: %s)", tc.name, got.PermissionDecision, tc.want, got.PermissionDecisionReason)
		}
	}
	// An unjudged candidate goes through, and the user is told why.
	if got := runHookWith(t, write(cases[2].content), cfg); !strings.Contains(got.SystemMessage, "no AI provider") {
		t.Errorf("offline note should say no AI provider is configured, got %q", got.SystemMessage)
	}
	// Sanity: with the heuristic chosen on purpose, the JWT does block.
	if got := runHookWith(t, write("token = \""+jwt+"\"\n"), noAI); got.PermissionDecision != "deny" {
		t.Fatalf("precondition: mode=off JWT decision = %q, want deny", got.PermissionDecision)
	}
}

// With no key configured, the hook must never adjudicate through a `claude`
// login it finds on PATH: that spends a subscription nobody chose and sends code
// to that account. It goes offline instead.
func TestHookNeverRunsClaudeImplicitly(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "claude-ran")
	stub := "#!/bin/sh\ntouch " + marker + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte(stub), 0o755); err != nil { // #nosec G306 -- test stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("KLARION_TEST_ABSENT_KEY", "")

	got := runHookWith(t, map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "app/config.py", "content": "aws_access_key_id = \"AKIA" + "Z7QW3MPLXV2KRT8N\"\n"},
	}, "[ai]\nmode = \"on\"\nprovider = \"anthropic\"\napi_key_env = \"KLARION_TEST_ABSENT_KEY\"\n")

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the hook ran the claude CLI without ai.provider = \"claude-cli\"")
	}
	if got.PermissionDecision != "deny" {
		t.Errorf("decision = %q, want deny from the offline check", got.PermissionDecision)
	}
}

// "allow" skips Claude Code's permission prompt. A secret scanner must never
// send it: installing Klarion would otherwise stop Claude Code from asking
// before any clean shell command or edit.
func TestHookNeverApprovesToolCalls(t *testing.T) {
	t.Setenv("KLARION_TEST_ABSENT_KEY", "")
	offline := "[ai]\nmode = \"on\"\nprovider = \"openai\"\napi_key_env = \"KLARION_TEST_ABSENT_KEY\"\n"
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	cases := []struct {
		name, cfg string
		payload   map[string]any
	}{
		{"clean write", noAI, map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "a.go", "content": "package a\n"}}},
		{"clean bash", noAI, map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls -la"}}},
		{"empty edit", noAI, map[string]any{"tool_name": "Edit", "tool_input": map[string]any{"file_path": "a.go", "new_string": ""}}},
		{"below block_on", noAI + "[hook]\nblock_on = \"critical\"\n", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "a.py", "content": "token = \"" + jwt + "\"\n"}}},
		{"offline, unjudged", offline, map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "a.py", "content": "api_token = \"" + "Zk9Qp2Vx7Lm4" + "Rn8Ty1WcQe3\"\n"}}},
	}
	for _, tc := range cases {
		got := runHookWith(t, tc.payload, tc.cfg)
		if got.PermissionDecision != "" || strings.Contains(got.Raw, "allow\"") {
			t.Errorf("%s: hook printed %q; it must not make a decision", tc.name, got.Raw)
		}
	}
}

// The block message must carry a fingerprint that, pasted into the allowlist as
// shown, actually lets the same content through. Without it a false positive
// is a dead end: computing the fingerprint means writing the value, which the
// hook blocks.
func TestHookFingerprintAllowlistsTheFinding(t *testing.T) {
	payload := map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": "keys.txt", "content": "aws_access_key_id = \"AKIA" + "Z7QW3MPLXV2KRT8N\"\n"},
	}
	got := runHookWith(t, payload, noAI)
	if got.PermissionDecision != "deny" {
		t.Fatalf("precondition: decision = %q, want deny", got.PermissionDecision)
	}
	m := regexp.MustCompile(`fingerprints = \["([0-9a-f]{32})"\]`).FindStringSubmatch(got.PermissionDecisionReason)
	if m == nil {
		t.Fatalf("no allowlist line in the reason: %q", got.PermissionDecisionReason)
	}
	if !strings.Contains(got.PermissionDecisionReason, "fingerprint "+m[1]) {
		t.Errorf("the finding line should show its fingerprint: %q", got.PermissionDecisionReason)
	}
	// Saving that line must not be blocked: a 32-character hex fingerprint reads
	// as a high-entropy secret to the offline check.
	edit := map[string]any{
		"tool_name":  "Edit",
		"tool_input": map[string]any{"file_path": ".klarion.toml", "new_string": "[allowlist]\nfingerprints = [\"" + m[1] + "\"]\n"},
	}
	if got := runHookWith(t, edit, noAI); got.PermissionDecision != "" {
		t.Errorf("editing .klarion.toml was blocked: %q", got.PermissionDecisionReason)
	}
	allowed := runHookWith(t, payload, noAI+"[allowlist]\nfingerprints = [\""+m[1]+"\"]\n")
	if allowed.PermissionDecision != "" {
		t.Errorf("after allowlisting the printed fingerprint: decision = %q, want none", allowed.PermissionDecision)
	}
	// Sanity: a different fingerprint does not let it through.
	other := runHookWith(t, payload, noAI+"[allowlist]\nfingerprints = [\"00000000000000000000000000000000\"]\n")
	if other.PermissionDecision != "deny" {
		t.Errorf("an unrelated fingerprint allowlisted the finding: decision = %q", other.PermissionDecision)
	}
}

func TestGitCommitIntent(t *testing.T) {
	cases := map[string]bool{
		"git commit -m wip":                     true,
		"git add -A && git commit -m 'wip'":     true,
		"cd app && git add .":                   true,
		"git -C sub commit -am x":               true,
		"git -c user.name=x commit -m y":        true,
		"git --no-pager stage config.py":        true,
		"(git add notes.txt)":                   true,
		"/usr/bin/git commit --amend --no-edit": true,
		"GIT_EDITOR=true git commit":            true,
		"make test; git commit -qm done":        true,
		"git status":                            false,
		"git log --grep=commit":                 false,
		"git diff --stat":                       false,
		"git config alias.ci commit":            false,
		"echo \"committed\" > log.txt":          false,
		"gitk --all":                            false,
		"npm run add":                           false,
	}
	for cmd, want := range cases {
		if got := gitCommitIntent(cmd); got != want {
			t.Errorf("gitCommitIntent(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// newHookRepo makes a throwaway git repository with one empty commit, isolated
// from the user's git config.
func newHookRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_AUTHOR_NAME", "Klarion Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@klarion.dev")
	t.Setenv("GIT_COMMITTER_NAME", "Klarion Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@klarion.dev")
	dir := t.TempDir()
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "init")
	return dir
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func writeRepoFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bashIn(dir, command string) map[string]any {
	return map[string]any{"tool_name": "Bash", "cwd": dir, "tool_input": map[string]any{"command": command}}
}

// The hook runs before the command, so for `git add -A && git commit` a secret
// the agent never wrote is not staged yet. It must still block.
func TestHookBlocksCommittingSecrets(t *testing.T) {
	awsKey := "AKIA" + "Z7QW3MPLXV2KRT8N"

	t.Run("untracked file, run from a subdirectory", func(t *testing.T) {
		repo := newHookRepo(t)
		writeRepoFile(t, repo, ".env", "AWS_ACCESS_KEY_ID="+awsKey+"\n")
		writeRepoFile(t, repo, "app/main.go", "package main\n")
		got := runHookWith(t, bashIn(filepath.Join(repo, "app"), "git add -A && git commit -m wip"), noAI)
		if got.PermissionDecision != "deny" {
			t.Fatalf("decision = %q, want deny (output %q)", got.PermissionDecision, got.Raw)
		}
		if !strings.Contains(got.PermissionDecisionReason, ".env") || !strings.Contains(got.PermissionDecisionReason, "git command") {
			t.Errorf("reason should name .env and the git command: %q", got.PermissionDecisionReason)
		}
		if strings.Contains(got.PermissionDecisionReason, awsKey) {
			t.Errorf("raw secret in the reason: %q", got.PermissionDecisionReason)
		}
	})

	t.Run("staged file", func(t *testing.T) {
		repo := newHookRepo(t)
		writeRepoFile(t, repo, "config.py", "aws_access_key_id = \""+awsKey+"\"\n")
		gitIn(t, repo, "add", "config.py")
		if got := runHookWith(t, bashIn(repo, "git commit -m 'add config'"), noAI); got.PermissionDecision != "deny" {
			t.Errorf("decision = %q, want deny", got.PermissionDecision)
		}
	})

	t.Run("unstaged change to a tracked file", func(t *testing.T) {
		repo := newHookRepo(t)
		writeRepoFile(t, repo, "app.py", "print('hi')\n")
		gitIn(t, repo, "add", "app.py")
		gitIn(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "app")
		writeRepoFile(t, repo, "app.py", "print('hi')\naws_access_key_id = \""+awsKey+"\"\n")
		if got := runHookWith(t, bashIn(repo, "git commit -am 'update'"), noAI); got.PermissionDecision != "deny" {
			t.Errorf("decision = %q, want deny", got.PermissionDecision)
		}
	})
}

// Blocking a commit for something it would not commit teaches people to
// uninstall the hook. Ignored files, secrets already in history, other git
// commands, and directories outside a repository must all go through.
func TestHookCommitScanStaysInScope(t *testing.T) {
	awsKey := "AKIA" + "Z7QW3MPLXV2KRT8N"

	t.Run("gitignored file and a secret already committed", func(t *testing.T) {
		repo := newHookRepo(t)
		writeRepoFile(t, repo, ".gitignore", ".env\n")
		writeRepoFile(t, repo, ".env", "AWS_ACCESS_KEY_ID="+awsKey+"\n")
		writeRepoFile(t, repo, "legacy.py", "aws_access_key_id = \""+awsKey+"\"\n")
		gitIn(t, repo, "add", ".gitignore", "legacy.py")
		gitIn(t, repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "old")
		writeRepoFile(t, repo, "legacy.py", "aws_access_key_id = \""+awsKey+"\"\nprint('unrelated change')\n")
		got := runHookWith(t, bashIn(repo, "git add -A && git commit -m wip"), noAI)
		if got.PermissionDecision != "" {
			t.Errorf("decision = %q, want none (reason %q)", got.PermissionDecision, got.PermissionDecisionReason)
		}
		// Committing Klarion's own config, full of fingerprints, is not a leak.
		writeRepoFile(t, repo, ".klarion.toml", "[allowlist]\nfingerprints = [\"37f6cd332ef64f4cb8df8d74d6fbf521\"]\n")
		if got := runHookWith(t, bashIn(repo, "git add -A && git commit -m allowlist"), noAI); got.PermissionDecision != "" {
			t.Errorf(".klarion.toml commit: decision = %q, want none (reason %q)", got.PermissionDecision, got.PermissionDecisionReason)
		}
		// Sanity: the same untracked secret without the ignore rule does block.
		writeRepoFile(t, repo, "notes.txt", "aws_access_key_id = \""+awsKey+"\"\n")
		if got := runHookWith(t, bashIn(repo, "git add -A && git commit -m wip"), noAI); got.PermissionDecision != "deny" {
			t.Errorf("precondition: unignored secret decision = %q, want deny", got.PermissionDecision)
		}
	})

	t.Run("other git commands", func(t *testing.T) {
		repo := newHookRepo(t)
		writeRepoFile(t, repo, "notes.txt", "aws_access_key_id = \""+awsKey+"\"\n")
		for _, cmd := range []string{"git status", "git log --grep=commit", "git diff"} {
			if got := runHookWith(t, bashIn(repo, cmd), noAI); got.Raw != "" {
				t.Errorf("%q: hook printed %q, want nothing", cmd, got.Raw)
			}
		}
	})

	t.Run("outside a repository", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not on PATH")
		}
		dir := t.TempDir()
		t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
		writeRepoFile(t, dir, "notes.txt", "aws_access_key_id = \""+awsKey+"\"\n")
		if got := runHookWith(t, bashIn(dir, "git commit -m x"), noAI); got.Raw != "" {
			t.Errorf("hook printed %q, want nothing", got.Raw)
		}
	})
}

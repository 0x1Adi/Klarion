package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/git"
	"github.com/0x1Adi/Klarion/internal/verify"
)

// hookInput is the subset of the Claude Code PreToolUse hook payload we read.
type hookInput struct {
	HookEventName string          `json:"hook_event_name"`
	ToolName      string          `json:"tool_name"`
	CWD           string          `json:"cwd"`
	ToolInput     json.RawMessage `json:"tool_input"`
}

type toolInput struct {
	FilePath  string     `json:"file_path"`
	Content   string     `json:"content"`    // Write
	NewString string     `json:"new_string"` // Edit
	Edits     []editItem `json:"edits"`      // MultiEdit
	Command   string     `json:"command"`    // Bash
}

type editItem struct {
	NewString string `json:"new_string"`
}

// preToolUseOutput is the Claude Code hook reply. A decision goes in
// hookSpecificOutput; a note for the transcript goes in systemMessage. A reply
// with neither is never written: no output leaves the call to Claude Code's
// normal permission flow.
type preToolUseOutput struct {
	HookSpecificOutput *hookSpecific `json:"hookSpecificOutput,omitempty"`
	SystemMessage      string        `json:"systemMessage,omitempty"`
}

type hookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"` // deny|ask; never allow
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

var (
	hookEvent string
	hookBash  bool
)

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Run as a Claude Code (or generic agent) PreToolUse hook",
	Long: `hook reads a PreToolUse event as JSON on stdin, scans the code the agent is
about to write, and for a git add or commit the changes that command could
commit. When a real secret is detected the tool call is denied (or the user is
asked, per [hook] decision), with the reason fed back so the agent can fix the
code instead of leaking.

It never approves a tool call: a clean result prints nothing, so Claude Code's
own permission prompts still apply. Fail-open by design: an internal error lets
the call continue, with a note, unless [hook] fail_open=false.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHook(cmd.Context(), os.Stdin, os.Stdout)
	},
}

func runHook(ctx context.Context, in io.Reader, out io.Writer) error {
	cfg, err := loadConfig()
	failOpen := cfg == nil || cfg.Hook.FailOpen
	if err != nil {
		return hookAllow(out, failOpen, fmt.Sprintf("config error: %v", err))
	}

	raw, err := io.ReadAll(io.LimitReader(in, 8<<20))
	if err != nil {
		return hookAllow(out, cfg.Hook.FailOpen, "could not read hook input")
	}
	var hi hookInput
	if err := json.Unmarshal(raw, &hi); err != nil {
		return hookAllow(out, cfg.Hook.FailOpen, "could not parse hook input")
	}
	var ti toolInput
	_ = json.Unmarshal(hi.ToolInput, &ti)

	// An agent edits the same files repeatedly; persisting verdicts keeps the
	// hook from re-adjudicating identical candidates on every edit.
	if cfg.AI.CachePath == "" {
		if dir, err := os.UserCacheDir(); err == nil {
			cfg.AI.CachePath = filepath.Join(dir, "klarion", "hook-verdicts.json")
		}
	}
	p, err := newPipeline(cfg)
	offline := false
	if err != nil && !strings.EqualFold(cfg.AI.Mode, "off") {
		// No AI provider. Allowing every write would make an unconfigured
		// install protect nothing, so check offline and block only
		// provider-issued keys, which never need a model to judge. Never fall
		// back to a model the operator did not configure (such as a local
		// `claude` login): that would send code to an account nobody chose.
		cfg.AI.Mode = "off"
		if p, err = newPipeline(cfg); err == nil {
			offline = true
			fmt.Fprintln(os.Stderr, "klarion: no AI provider available; blocking provider credentials only")
		}
	}
	if err != nil {
		return hookAllow(out, cfg.Hook.FailOpen, fmt.Sprintf("pipeline error: %v", err))
	}
	defer p.Close()

	path, text := extractScanTarget(hi, ti)
	bash := hi.ToolName == "Bash" || hookBash
	commit := bash && gitCommitIntent(ti.Command)
	if (strings.TrimSpace(text) == "" && !commit) || (!bash && klarionFile(path)) {
		return hookAllow(out, true, "")
	}

	var candidates []finding.Finding
	if strings.TrimSpace(text) != "" {
		candidates = p.detector.ScanContent(path, []byte(text))
	}
	unscanned := ""
	if commit {
		fs, err := scanUncommitted(ctx, p, hookDir(hi))
		if err != nil {
			unscanned = fmt.Sprintf("could not read what this git command would commit: %v", err)
		}
		candidates = append(candidates, fs...)
	}
	if len(candidates) == 0 {
		return hookAllow(out, cfg.Hook.FailOpen, unscanned)
	}
	active, _, err := p.verdictAndFilter(ctx, candidates)
	if err != nil {
		return hookAllow(out, cfg.Hook.FailOpen, fmt.Sprintf("verify error: %v", err))
	}

	blockOn := finding.ParseSeverity(cfg.Hook.BlockOn)
	blocking := filterSeverity(active, blockOn)
	if offline {
		var provider []finding.Finding
		for i := range blocking {
			if verify.IsProviderCredential(&blocking[i]) {
				provider = append(provider, blocking[i])
			}
		}
		blocking = provider
		if len(blocking) == 0 && len(active) > 0 && unscanned == "" {
			return writeNote(out, fmt.Sprintf("Klarion could not judge %d candidate(s): no AI provider "+
				"is configured (set an API key or ai.provider). Offline, only provider keys are blocked.", len(active)))
		}
	}
	if len(blocking) == 0 {
		return hookAllow(out, cfg.Hook.FailOpen, unscanned)
	}

	decision := cfg.Hook.Decision
	if decision != "ask" {
		decision = "deny"
	}
	return writeDecision(out, decision, blockReason(blocking, commit))
}

// gitCommitIntent reports whether a shell command runs git add, git stage or
// git commit. It reads the words of each simple command, skips git's global
// options, and checks the subcommand, so `git log --grep=commit` does not count.
// Git aliases (`git ci`) and wrappers such as lazygit are not recognised.
func gitCommitIntent(command string) bool {
	for _, segment := range shellSeparators.Split(command, -1) {
		words := strings.Fields(segment)
		for i, w := range words {
			w = strings.Trim(w, `"'`)
			if w != "git" && !strings.HasSuffix(w, "/git") {
				continue
			}
			j := i + 1
			for j < len(words) && strings.HasPrefix(words[j], "-") {
				opt := words[j]
				j++
				if gitOptionsWithValue[opt] {
					j++ // the value is the next word, as in -C dir or -c key=value
				}
			}
			if j < len(words) {
				switch strings.Trim(words[j], `"'`) {
				case "add", "stage", "commit":
					return true
				}
			}
		}
	}
	return false
}

// shellSeparators splits a command line into simple commands.
var shellSeparators = regexp.MustCompile(`&&|\|\||[;|&\n()]`)

// gitOptionsWithValue are git's global options that take the next word as
// their value when written without "=".
var gitOptionsWithValue = map[string]bool{
	"-C": true, "-c": true, "--git-dir": true, "--work-tree": true,
	"--namespace": true, "--super-prefix": true, "--config-env": true,
}

// klarionFile reports whether path is Klarion's own config or state. Their
// content is fingerprints, rule patterns and cache keys, which read as
// high-entropy secrets: scanning them would block the very allowlist edit a
// block message asks for. Scans skip them through the default ignore paths.
func klarionFile(path string) bool {
	switch filepath.Base(path) {
	case ".klarion.toml", "klarion.toml", ".klarion-baseline.json":
		return true
	}
	return strings.Contains("/"+filepath.ToSlash(path), "/.klarion/")
}

// hookDir is the directory the agent's command runs in.
func hookDir(hi hookInput) string {
	if hi.CWD != "" {
		return hi.CWD
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

// scanUncommitted scans what the next commit in dir's repository could contain:
// the changed lines of tracked files and whole untracked files, with the same
// ignore, allowlist and size rules as a staged scan. Only the repository the
// session runs in is read: following a `cd` or `git -C` into another repository
// would run git under that repository's config, which the user never trusted.
// Outside a repository there is nothing to scan and the git command fails on its
// own.
func scanUncommitted(ctx context.Context, p *pipeline, dir string) ([]finding.Finding, error) {
	if !git.IsRepo(ctx, dir) {
		return nil, nil
	}
	root, err := git.RepoRoot(ctx, dir)
	if err != nil {
		return nil, err
	}
	diffs, untracked, err := git.UncommittedChanges(ctx, root)
	if err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, d := range diffs {
		if p.cfg.PathIgnored(d.Path) || p.cfg.PathAllowlisted(d.Path) {
			continue
		}
		out = append(out, p.detector.ScanLines(d.Path, d.Added)...)
	}
	for _, rel := range untracked {
		if p.cfg.PathIgnored(rel) || p.cfg.PathAllowlisted(rel) {
			continue
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(abs)
		if err != nil || !info.Mode().IsRegular() || info.Size() > p.cfg.Scan.MaxFileSizeBytes {
			continue
		}
		content, err := os.ReadFile(abs) // #nosec G304 -- a regular file git listed inside the repository
		if err != nil {
			continue
		}
		out = append(out, p.detector.ScanContent(rel, content)...)
	}
	return out, nil
}

// extractScanTarget returns a path label and the text to scan for the event.
// For Bash it is the command text (secrets pasted inline); what a git add or
// commit would commit is scanned separately by scanUncommitted.
func extractScanTarget(hi hookInput, ti toolInput) (path, text string) {
	if hi.ToolName == "Bash" || hookBash {
		return "<bash-command>", ti.Command
	}
	path = ti.FilePath
	if path == "" {
		path = "<agent-write>"
	} else if hi.CWD != "" && filepath.IsAbs(path) {
		// Judge the path inside the project. Claude Code sends absolute paths,
		// and a parent directory named "examples" or "test" would otherwise
		// mark every file as a fixture.
		if rel, err := filepath.Rel(hi.CWD, path); err == nil && rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			path = rel
		}
	}
	switch {
	case ti.Content != "":
		return path, ti.Content
	case len(ti.Edits) > 0:
		var b strings.Builder
		for _, e := range ti.Edits {
			b.WriteString(e.NewString)
			b.WriteByte('\n')
		}
		return path, b.String()
	default:
		return path, ti.NewString
	}
}

func filterSeverity(fs []finding.Finding, min finding.Severity) []finding.Finding {
	var out []finding.Finding
	for i := range fs {
		if fs[i].Severity.Rank() >= min.Rank() {
			out = append(out, fs[i])
		}
	}
	return out
}

// blockReason explains a block to the agent. It shows each finding's fingerprint
// and the exact allowlist line, because a false positive is otherwise a dead end:
// the agent cannot compute a fingerprint without writing the value somewhere,
// and the hook blocks that too. The value itself is never included.
func blockReason(fs []finding.Finding, commit bool) string {
	var b strings.Builder
	fromFiles := false
	for _, f := range fs {
		if f.FilePath != "<bash-command>" {
			fromFiles = true
		}
	}
	if commit && fromFiles {
		b.WriteString("Klarion blocked this git command: it could commit leaked secret(s).\n")
	} else {
		b.WriteString("Klarion blocked this action: it would introduce leaked secret(s).\n")
	}
	var quoted []string
	seen := map[string]bool{}
	for _, f := range fs {
		detail := ""
		if f.Verdict.Confidence > 0 {
			detail = fmt.Sprintf("confidence %.0f%%, ", f.Verdict.Confidence*100)
		}
		fp := f.Fingerprint
		if fp == "" {
			fp = f.ComputeFingerprint()
		}
		fmt.Fprintf(&b, "  • %s in %s:%d — %s (%sfingerprint %s)\n", f.Description, f.FilePath, f.Line, f.Redacted, detail, fp)
		if !seen[fp] {
			seen[fp] = true
			quoted = append(quoted, strconv.Quote(fp))
		}
	}
	b.WriteString("Remove the secret (use an environment variable or a secret manager) and retry.")
	if commit && fromFiles {
		b.WriteString(" If a file should never be committed, add it to .gitignore.")
	}
	fmt.Fprintf(&b, "\nIf the user confirms a finding is not a real secret, add its fingerprint under [allowlist] in .klarion.toml:\n"+
		"fingerprints = [%s]\nAsk the user first. Do not add it on your own.", strings.Join(quoted, ", "))
	return b.String()
}

// hookAllow lets the tool call continue through Claude Code's normal permission
// flow. It never answers "allow": that answer skips the permission prompt, so a
// scanner that approved every clean call would silently switch off the user's
// approval of shell commands and edits. With no reason it prints nothing. A
// reason becomes a note in the transcript, so a scanner that stopped scanning
// is visible, or a denial when the operator set fail_open = false.
func hookAllow(out io.Writer, failOpen bool, reason string) error {
	if reason == "" {
		return nil
	}
	if !failOpen {
		return writeDecision(out, "deny", "Klarion could not verify safety: "+reason)
	}
	return writeNote(out, "Klarion did not scan this change: "+reason)
}

// writeDecision prints a deny or ask decision.
func writeDecision(out io.Writer, decision, reason string) error {
	return json.NewEncoder(out).Encode(preToolUseOutput{HookSpecificOutput: &hookSpecific{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}})
}

// writeNote prints a message for the transcript without making a decision.
func writeNote(out io.Writer, msg string) error {
	return json.NewEncoder(out).Encode(preToolUseOutput{SystemMessage: msg})
}

func init() {
	hookCmd.Flags().StringVar(&hookEvent, "event", "pre-tool-use", "hook event name")
	hookCmd.Flags().BoolVar(&hookBash, "bash", false, "treat the payload as a Bash tool call")
	rootCmd.AddCommand(hookCmd)
}

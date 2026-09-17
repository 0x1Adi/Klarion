package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/finding"
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

// preToolUseOutput is the Claude Code hook decision envelope.
type preToolUseOutput struct {
	HookSpecificOutput hookSpecific `json:"hookSpecificOutput"`
}

type hookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"` // allow|deny|ask
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
about to write (or the commit it is about to make), and prints a permission
decision as JSON on stdout. When a real secret is detected the tool call is
denied (or the agent is asked, per [hook] decision), with the reason fed back
so the agent can fix the code instead of leaking.

Fail-open by design: any internal error allows the tool call (unless
[hook] fail_open=false), so the scanner never wedges the agent.`,
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
	if strings.TrimSpace(text) == "" {
		return hookAllow(out, true, "")
	}

	candidates := p.detector.ScanContent(path, []byte(text))
	if len(candidates) == 0 {
		return hookAllow(out, true, "")
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
		if len(blocking) == 0 && len(active) > 0 {
			return writeDecision(out, "allow", fmt.Sprintf("Klarion could not judge %d candidate(s): no AI provider "+
				"is configured (set an API key or ai.provider). Offline, only provider keys are blocked.", len(active)))
		}
	}
	if len(blocking) == 0 {
		return hookAllow(out, true, "")
	}

	decision := cfg.Hook.Decision
	if decision != "ask" {
		decision = "deny"
	}
	return writeDecision(out, decision, blockReason(blocking))
}

// extractScanTarget returns a path label and the text to scan for the event.
// For Bash commits we scan the command text itself (secrets pasted inline);
// staged-content scanning is handled by the pre-commit hook / `klarion git`.
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

func blockReason(fs []finding.Finding) string {
	var b strings.Builder
	b.WriteString("Klarion blocked this action: it would introduce leaked secret(s).\n")
	for _, f := range fs {
		conf := ""
		if f.Verdict.Confidence > 0 {
			conf = fmt.Sprintf(" (confidence %.0f%%)", f.Verdict.Confidence*100)
		}
		fmt.Fprintf(&b, "  • %s in %s:%d — %s%s\n", f.Description, f.FilePath, f.Line, f.Redacted, conf)
	}
	b.WriteString("Remove the secret (use an environment variable or a secret manager) and retry. ")
	b.WriteString("If this is a confirmed false positive, add its fingerprint to .klarion.toml allowlist.")
	return b.String()
}

// hookAllow emits an allow decision. When failOpen is false and reason is set,
// it instead denies (used when the operator opted out of fail-open). A fail-open
// allow carries the reason, which Claude Code shows the user, so a scanner that
// silently stopped scanning is visible.
func hookAllow(out io.Writer, failOpen bool, reason string) error {
	if reason == "" {
		return writeDecision(out, "allow", "")
	}
	if !failOpen {
		return writeDecision(out, "deny", "Klarion could not verify safety: "+reason)
	}
	return writeDecision(out, "allow", "Klarion did not scan this change: "+reason)
}

func writeDecision(out io.Writer, decision, reason string) error {
	env := preToolUseOutput{HookSpecificOutput: hookSpecific{
		HookEventName:            "PreToolUse",
		PermissionDecision:       decision,
		PermissionDecisionReason: reason,
	}}
	enc := json.NewEncoder(out)
	return enc.Encode(env)
}

func init() {
	hookCmd.Flags().StringVar(&hookEvent, "event", "pre-tool-use", "hook event name")
	hookCmd.Flags().BoolVar(&hookBash, "bash", false, "treat the payload as a Bash tool call")
	rootCmd.AddCommand(hookCmd)
}

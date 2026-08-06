// Command klarion is the AI-native secret scanner: a fast Rényi-entropy +
// curated-rule pass with LLM adjudication of every candidate.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/config"
)

// Populated via -ldflags at release time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// errFindings signals "scan succeeded, secrets found" — mapped to exit code 1
// (exit 2 is reserved for operational errors), matching scanner conventions.
var errFindings = errors.New("potential secrets detected")

var (
	flagConfig  string
	flagNoColor bool
	flagQuiet   bool
	flagVerbose bool
)

var rootCmd = &cobra.Command{
	Use:   "klarion",
	Short: "AI-native secret scanner — Rényi entropy speed, LLM judgment",
	Long: `Klarion detects secrets leaked into code — including code written by AI
agents — using a two-stage pipeline:

  1. Fast pass: curated rules for known key formats plus a normalized
     Rényi-entropy sweep that flags anything statistically indistinguishable
     from random key material.
  2. Verdict pass: each candidate, with its surrounding context, is
     adjudicated by an AI verifier (or returned to the calling agent in hook
     and MCP modes) to separate real leaks from placeholders and fixtures.

Run it standalone, as a git pre-commit hook, in CI (GitHub/GitLab), as a
Claude Code hook, or as an MCP server.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.StringVar(&flagConfig, "config", "", "path to config file (default: auto-discover .klarion.toml)")
	pf.BoolVar(&flagNoColor, "no-color", false, "disable colored output")
	pf.BoolVarP(&flagQuiet, "quiet", "q", false, "suppress non-essential output")
	pf.BoolVarP(&flagVerbose, "verbose", "v", false, "verbose diagnostics on stderr")
}

// loadConfig resolves configuration honoring --config, then $KLARION_CONFIG,
// then .klarion.toml discovery from the working directory upward.
func loadConfig() (*config.Config, error) {
	if flagConfig != "" {
		return config.Load(flagConfig)
	}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	cfg, src, err := config.FindAndLoad(wd)
	if err != nil {
		return nil, err
	}
	if flagVerbose && src != "" {
		fmt.Fprintf(os.Stderr, "klarion: config loaded from %s\n", src)
	}
	return cfg, nil
}

func main() {
	err := rootCmd.Execute()
	switch {
	case err == nil:
	case errors.Is(err, errFindings):
		os.Exit(1)
	default:
		fmt.Fprintln(os.Stderr, "klarion:", err)
		os.Exit(2)
	}
}

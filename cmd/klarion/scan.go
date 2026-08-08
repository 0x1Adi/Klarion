package main

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/scan"
)

var (
	scanFormat    string
	scanFailOn    string
	scanNoAI      bool
	scanAIMode    string
	scanShowSec   bool
	scanShowSup   bool
	scanCachePath string
	scanBaseline  string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path ...]",
	Short: "Scan files or directories for leaked secrets",
	Long: `Scan walks the given paths (default: current directory), runs the fast
Rényi-entropy + rules pass, adjudicates each candidate with the AI verifier,
and reports real leaks. Exit code 1 means secrets were found at or above the
--fail-on severity; exit 2 means an operational error.

Klarion requires an AI verifier. The entropy pass is a cost-reduction filter
that narrows the candidate set so the model reads hundreds of strings instead
of millions; it is not a detector on its own. Without a verifier the output is
raw candidates, which includes ordinary identifiers, certificates and vendored
code. Set an API key, or point ai.provider at a local ollama model.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !validAIMode(scanAIMode) {
			return fmt.Errorf("invalid --ai-mode %q: want auto, on, or off", scanAIMode)
		}
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		applyOutputFlags(cfg)

		roots := args
		if len(roots) == 0 {
			roots = []string{"."}
		}

		p, err := newPipeline(cfg)
		if err != nil {
			return err
		}
		defer p.Close()

		start := time.Now()
		scanner := scan.New(cfg, p.detector)
		candidates, filesScanned, err := scanner.ScanPaths(cmd.Context(), roots)
		if err != nil {
			return err
		}
		active, suppressed, err := p.verdictAndFilter(cmd.Context(), candidates)
		if err != nil {
			return err
		}
		return p.writeReport(active, suppressed, filesScanned, time.Since(start), finding.ParseSeverity(scanFailOn))
	},
}

// applyOutputFlags overlays the common output/AI flags onto the loaded config.
func applyOutputFlags(cfg *config.Config) {
	if scanFormat != "" {
		cfg.Report.Format = scanFormat
	}
	// --ai-mode is the general form; --no-ai is the shorthand for "off" and
	// wins when both are given, since it is the more conservative choice.
	if scanAIMode != "" {
		cfg.AI.Mode = scanAIMode
	}
	if scanNoAI {
		cfg.AI.Mode = "off"
	}
	if scanShowSec {
		cfg.Report.Redact = false
	}
	if scanShowSup {
		cfg.Report.ShowSuppressed = true
	}
	// Paths are overridden rather than merged into a config file, so CI can set
	// them without having to synthesize TOML on top of the project's own.
	if scanCachePath != "" {
		cfg.AI.CachePath = scanCachePath
	}
	if scanBaseline != "" {
		cfg.Baseline.Path = scanBaseline
	}
}

// validAIMode reports whether m is an accepted --ai-mode value.
func validAIMode(m string) bool {
	switch m {
	case "", "auto", "on", "off":
		return true
	}
	return false
}

func init() {
	f := scanCmd.Flags()
	f.StringVarP(&scanFormat, "format", "f", "", "output format: text|json|sarif|junit|gitlab")
	f.StringVar(&scanFailOn, "fail-on", "low", "minimum severity that fails the scan (low|medium|high|critical)")
	f.BoolVar(&scanNoAI, "no-ai", false, "disable AI verification; same as --ai-mode off. Reports raw entropy candidates and is not a supported way to scan")
	f.StringVar(&scanAIMode, "ai-mode", "", "AI verification mode: auto|on|off (default: config value, normally auto)")
	f.BoolVar(&scanShowSec, "show-secrets", false, "show raw secrets in output (DANGEROUS)")
	f.BoolVar(&scanShowSup, "show-suppressed", false, "also report findings the verifier suppressed, with reasons")
	f.StringVar(&scanCachePath, "cache-path", "", "persist AI verdicts to `file` and reuse them on later runs (default: ai.cache_path)")
	f.StringVar(&scanBaseline, "baseline", "", "path to a baseline of accepted findings to suppress (default: baseline.path)")
	rootCmd.AddCommand(scanCmd)
}

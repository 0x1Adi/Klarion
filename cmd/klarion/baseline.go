package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/baseline"
	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/scan"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage the accepted-findings baseline",
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create [path ...]",
	Short: "Create/refresh the baseline from the current findings",
	Long: `Scans the given paths and records every detected finding (pre-verification)
into the baseline file. Subsequent scans suppress these known fingerprints, so
you can adopt klarion on a legacy codebase without drowning in pre-existing
findings and still catch anything new.`,
	Args: cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		det, err := detect.New(cfg)
		if err != nil {
			return err
		}
		roots := args
		if len(roots) == 0 {
			roots = []string{"."}
		}
		scanner := scan.New(cfg, det)
		findings, _, err := scanner.ScanPaths(cmd.Context(), roots)
		if err != nil {
			return err
		}
		bl := baseline.FromFindings(findings)
		if err := bl.Save(cfg.Baseline.Path); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "klarion: baseline written to %s (%d findings)\n", cfg.Baseline.Path, len(findings))
		return nil
	},
}

func init() {
	baselineCmd.AddCommand(baselineCreateCmd)
	rootCmd.AddCommand(baselineCmd)
}

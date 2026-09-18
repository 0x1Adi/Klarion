package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/mcp"
	"github.com/0x1Adi/Klarion/internal/verify"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run as a Model Context Protocol server (stdio)",
	Long: `mcp starts a Model Context Protocol server speaking JSON-RPC over stdio. It
exposes three tools — scan_text, scan_file, and verify_finding — so an AI agent
can check content for leaked secrets before writing or committing it. Point an
MCP-capable client (Claude Code, etc.) at "klarion mcp".`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		det, err := detect.New(cfg)
		if err != nil {
			return err
		}
		v, err := verify.Build(&cfg.AI)
		if err != nil {
			if !validAIMode(cfg.AI.Mode) {
				return err // a bad ai.mode is a config error, not a missing key
			}
			// No provider. Unlike a CLI run, an MCP session always has an agent
			// on the other end, so the server starts and returns candidates plus
			// the decision rules for that agent to judge, rather than refusing
			// to run. Never a model the operator did not configure.
			fmt.Fprintf(os.Stderr, "klarion mcp: %v\n", err)
			fmt.Fprintln(os.Stderr, "klarion mcp: no AI provider configured; the calling agent will be asked to judge candidates")
			v = nil
		}
		// Flush the verdict cache when the client disconnects: an MCP session
		// is long-lived and adjudicates the same candidates repeatedly.
		if c, ok := v.(interface{ Close() error }); ok {
			defer func() { _ = c.Close() }()
		}
		srv := mcp.New(cfg, det, v, version)
		return srv.Serve(cmd.Context(), os.Stdin, os.Stdout)
	},
}

func init() { rootCmd.AddCommand(mcpCmd) }

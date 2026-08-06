package main

import (
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
			return err
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

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/git"
)

const preCommitHook = `#!/bin/sh
# Installed by 'klarion protect'. Blocks commits that would introduce secrets.
# Remove this file (or run 'git commit --no-verify') to bypass.
if command -v klarion >/dev/null 2>&1; then
  klarion git || exit $?
else
  echo "klarion: binary not found on PATH; skipping secret scan" >&2
fi
`

var protectForce bool

var protectCmd = &cobra.Command{
	Use:   "protect [dir]",
	Short: "Install a git pre-commit hook that runs klarion",
	Long: `protect installs a pre-commit hook into the repository's hooks directory.
The hook runs 'klarion git' on every commit and blocks it if a real secret is
detected. Use --force to overwrite an existing pre-commit hook.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir := "."
		if len(args) == 1 {
			dir = args[0]
		}
		ctx := cmd.Context()
		if !git.IsRepo(ctx, dir) {
			return fmt.Errorf("%s is not a git repository", dir)
		}
		// Honor core.hooksPath: installing into .git/hooks when git is
		// configured to look elsewhere would report success and protect
		// nothing.
		hooksDir, err := git.HooksDir(ctx, dir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(hooksDir, 0o750); err != nil {
			return err
		}
		hookPath := filepath.Join(hooksDir, "pre-commit")
		if _, err := os.Stat(hookPath); err == nil && !protectForce {
			return fmt.Errorf("pre-commit hook already exists at %s (use --force to overwrite)", hookPath)
		}
		// 0755 is not optional: git refuses to run a hook that is not
		// executable, and the hook is a script the user may also inspect.
		if err := os.WriteFile(hookPath, []byte(preCommitHook), 0o755); err != nil { // #nosec G306 -- git hooks must be executable
			return err
		}
		fmt.Fprintf(os.Stdout, "klarion: installed pre-commit hook at %s\n", hookPath)
		return nil
	},
}

func init() {
	protectCmd.Flags().BoolVar(&protectForce, "force", false, "overwrite an existing pre-commit hook")
	rootCmd.AddCommand(protectCmd)
}

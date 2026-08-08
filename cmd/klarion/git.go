package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/git"
)

var (
	gitHistory    bool
	gitMaxCommits int
	gitSince      string
	gitFailOn     string
	gitBase       string
	gitHead       string
	gitRange      string
)

var gitCmd = &cobra.Command{
	Use:   "git [dir]",
	Short: "Scan staged changes (or history) in a git repository",
	Long: `By default, git scans the files currently staged in the index — the exact
content that a commit would introduce — making it ideal for a pre-commit hook.

With --base (and optionally --head) it scans only the commits a branch adds,
which is what you want in CI on a pull request: the build fails on secrets the
change introduces, not on ones that were already in the repository. The range
starts at the merge base, so commits that landed on the base branch after this
one was cut are not attributed to it.

With --history it walks past commits and reports secrets introduced anywhere in
the range, so you can audit a repository for previously-leaked credentials.`,
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

		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		applyOutputFlags(cfg)
		p, err := newPipeline(cfg)
		if err != nil {
			return err
		}
		defer p.Close()

		rng, err := resolveRange(ctx, dir)
		if err != nil {
			return err
		}

		start := time.Now()
		var candidates []finding.Finding
		var scanned int
		switch {
		case rng != "":
			candidates, scanned, err = scanRange(ctx, p, dir, rng)
		case gitHistory:
			candidates, scanned, err = scanHistory(ctx, p, dir)
		default:
			candidates, scanned, err = scanStaged(ctx, p, dir, cfg)
		}
		if err != nil {
			return err
		}

		active, suppressed, err := p.verdictAndFilter(ctx, candidates)
		if err != nil {
			return err
		}
		return p.writeReport(active, suppressed, scanned, time.Since(start), finding.ParseSeverity(gitFailOn))
	},
}

func scanStaged(ctx context.Context, p *pipeline, dir string, cfg *config.Config) ([]finding.Finding, int, error) {
	files, err := git.StagedFiles(ctx, dir)
	if err != nil {
		return nil, 0, err
	}
	var out []finding.Finding
	scanned := 0
	for _, f := range files {
		if cfg.PathIgnored(f.Path) || cfg.PathAllowlisted(f.Path) {
			continue
		}
		if int64(len(f.Content)) > cfg.Scan.MaxFileSizeBytes {
			continue
		}
		scanned++
		out = append(out, p.detector.ScanContent(f.Path, f.Content)...)
	}
	return out, scanned, nil
}

// resolveRange turns the --base/--head/--range flags into a git revision range,
// or "" when none was requested.
//
// --base is resolved through the merge base so a moving base branch does not
// leak other people's commits into this branch's diff. A base that is not in
// the local clone (the usual cause is a shallow CI checkout) is reported as an
// actionable error rather than silently scanning the wrong thing.
func resolveRange(ctx context.Context, dir string) (string, error) {
	if gitRange != "" {
		if gitBase != "" || gitHead != "" {
			return "", fmt.Errorf("--range cannot be combined with --base/--head")
		}
		if err := git.ValidateRange(gitRange); err != nil {
			return "", err
		}
		return gitRange, nil
	}
	if gitBase == "" {
		if gitHead != "" {
			return "", fmt.Errorf("--head requires --base")
		}
		return "", nil
	}

	head := gitHead
	if head == "" {
		head = "HEAD"
	}
	for _, rev := range []struct{ name, val string }{{"--base", gitBase}, {"--head", head}} {
		if err := git.ValidateRange(rev.val); err != nil {
			return "", err
		}
		if !git.HasRevision(ctx, dir, rev.val) {
			return "", fmt.Errorf("%s %q is not present in this clone — "+
				"fetch it first (in CI, check out with fetch-depth: 0)", rev.name, rev.val)
		}
	}

	base, err := git.MergeBase(ctx, dir, gitBase, head)
	if err != nil {
		return "", fmt.Errorf("no common ancestor between %q and %q: %w", gitBase, head, err)
	}
	return base + ".." + head, nil
}

// scanRange scans only the commits a range introduces.
func scanRange(ctx context.Context, p *pipeline, dir, rng string) ([]finding.Finding, int, error) {
	if flagVerbose {
		fmt.Fprintf(os.Stderr, "klarion: scanning commit range %s\n", rng)
	}
	return scanHunks(ctx, p, dir, git.HistoryOptions{Range: rng})
}

func scanHistory(ctx context.Context, p *pipeline, dir string) ([]finding.Finding, int, error) {
	return scanHunks(ctx, p, dir, git.HistoryOptions{MaxCommits: gitMaxCommits, Since: gitSince})
}

// scanHunks is the shared body of the history and range scans: walk the
// selected commits and scan the lines each one adds.
func scanHunks(ctx context.Context, p *pipeline, dir string, opts git.HistoryOptions) ([]finding.Finding, int, error) {
	hunks, err := git.ScanHistory(ctx, dir, opts)
	if err != nil {
		return nil, 0, err
	}
	var out []finding.Finding
	for _, h := range hunks {
		if p.cfg.PathIgnored(h.Path) || p.cfg.PathAllowlisted(h.Path) {
			continue
		}
		fs := p.detector.ScanLines(h.Path, h.Lines)
		for i := range fs {
			fs[i].Commit = h.Commit.Hash
			fs[i].Author = h.Commit.Author
			fs[i].Email = h.Commit.Email
			fs[i].Date = h.Commit.Date
			fs[i].Message = h.Commit.Message
			fs[i].Fingerprint = fs[i].ComputeFingerprint()
		}
		out = append(out, fs...)
	}
	return out, len(hunks), nil
}

func init() {
	f := gitCmd.Flags()
	f.StringVar(&gitBase, "base", "", "scan only commits this branch adds relative to `rev` (e.g. main, or a PR base SHA)")
	f.StringVar(&gitHead, "head", "", "with --base, the tip of the range (default HEAD)")
	f.StringVar(&gitRange, "range", "", "explicit git revision range to scan, e.g. `main..HEAD` (alternative to --base/--head)")
	f.BoolVar(&gitHistory, "history", false, "scan commit history instead of the staged index")
	f.IntVar(&gitMaxCommits, "max-commits", 0, "with --history, limit to the most recent N commits (0 = all)")
	f.StringVar(&gitSince, "since", "", "with --history, only commits since this date/ref (git --since syntax)")
	f.StringVar(&gitFailOn, "fail-on", "low", "minimum severity that fails the scan")
	f.StringVarP(&scanFormat, "format", "f", "", "output format: text|json|sarif|junit|gitlab")
	f.BoolVar(&scanNoAI, "no-ai", false, "disable AI verification. Reports raw entropy candidates and is not a supported way to scan")
	// Parity with `scan`: CI drives both through the same inputs.
	f.StringVar(&scanAIMode, "ai-mode", "", "AI verification mode: auto|on|off (default: config value, normally auto)")
	f.BoolVar(&scanShowSup, "show-suppressed", false, "also report findings the verifier suppressed, with reasons")
	f.StringVar(&scanCachePath, "cache-path", "", "persist AI verdicts to `file` and reuse them on later runs (default: ai.cache_path)")
	f.StringVar(&scanBaseline, "baseline", "", "path to a baseline of accepted findings to suppress (default: baseline.path)")
	rootCmd.AddCommand(gitCmd)
}

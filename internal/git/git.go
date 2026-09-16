package git

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/0x1Adi/Klarion/internal/detect"
)

// run executes git in dir and returns stdout. Stderr is folded into the error
// so callers get git's own diagnostic (e.g. "not a git repository") verbatim.
// Every git invocation goes through here so context cancellation and the
// working directory are handled uniformly.
func run(ctx context.Context, dir string, args ...string) ([]byte, error) {
	// #nosec G204 -- "git" is a fixed binary and args are passed as an argv
	// slice (no shell). Caller-supplied revisions are validated by
	// ValidateRange before they reach here.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, msg)
	}
	return stdout.Bytes(), nil
}

// IsRepo reports whether dir is inside a git working tree. It swallows all
// errors: a missing git binary or a non-repo directory both mean "no".
func IsRepo(ctx context.Context, dir string) bool {
	out, err := run(ctx, dir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "true"
}

// RepoRoot returns the absolute path of the repository's top-level directory.
func RepoRoot(ctx context.Context, dir string) (string, error) {
	out, err := run(ctx, dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// HooksDir returns the directory git will actually look in for hooks.
//
// It is not always <root>/.git/hooks: core.hooksPath (set by husky, the
// pre-commit framework, or a corporate template) redirects git elsewhere, and
// a hook installed in the default location is then silently never run. For a
// tool whose whole job is to block commits, installing a hook git ignores while
// reporting success is worse than refusing to install.
//
// A relative core.hooksPath is interpreted relative to the repository root,
// matching git's own behavior.
func HooksDir(ctx context.Context, dir string) (string, error) {
	root, err := RepoRoot(ctx, dir)
	if err != nil {
		return "", err
	}
	// A missing config key exits non-zero; that is the common case, not an error.
	if out, err := run(ctx, dir, "config", "--get", "core.hooksPath"); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			if filepath.IsAbs(p) {
				return p, nil
			}
			return filepath.Join(root, p), nil
		}
	}
	// git rev-parse --git-dir resolves worktrees and submodules, where the
	// real git directory is not <root>/.git.
	if out, err := run(ctx, dir, "rev-parse", "--absolute-git-dir"); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return filepath.Join(p, "hooks"), nil
		}
	}
	return filepath.Join(root, ".git", "hooks"), nil
}

// StagedFile is a path in the index together with the exact blob content that
// would be committed — not the working-tree version, which may differ.
type StagedFile struct {
	Path    string
	Content []byte
}

// StagedFiles returns the files staged for commit (added, copied, or modified)
// each paired with its staged blob. Deletions are excluded by the
// --diff-filter=ACM filter, since there is nothing to scan. The staged content
// is read via `git show :path`, which addresses the index copy regardless of
// what is currently in the working tree.
func StagedFiles(ctx context.Context, dir string) ([]StagedFile, error) {
	out, err := run(ctx, dir,
		"diff", "--cached", "--name-only", "--diff-filter=ACM", "-z")
	if err != nil {
		return nil, err
	}
	paths := splitNUL(out)
	files := make([]StagedFile, 0, len(paths))
	for _, p := range paths {
		// ":path" resolves to the staged (index) blob. Errors here are fatal:
		// a listed staged path should always be readable.
		content, err := run(ctx, dir, "show", ":"+p)
		if err != nil {
			return nil, err
		}
		files = append(files, StagedFile{Path: p, Content: content})
	}
	return files, nil
}

// TrackedFiles lists every file git tracks in dir, as repo-relative paths.
func TrackedFiles(ctx context.Context, dir string) ([]string, error) {
	out, err := run(ctx, dir, "ls-files", "-z")
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// Commit identifies the authorship of a change; it is attached to every
// history hunk so findings can be blamed on a specific commit.
type Commit struct {
	Hash    string
	Author  string
	Email   string
	Date    string
	Message string
}

// HistoryHunk is the added content of one file within one commit. Lines carry
// their new-file line numbers so a finding maps to a real location in the
// blob as of that commit.
type HistoryHunk struct {
	Commit Commit
	Path   string
	Lines  []detect.Line
}

// HistoryOptions bounds a history scan. The zero value scans the history
// reachable from every ref: all branches, tags, remotes and the stash.
type HistoryOptions struct {
	MaxCommits int    // 0 = unbounded
	Since      string // any git approxidate, e.g. "2 weeks ago"; "" = no bound
	// Range limits the scan to a commit range, e.g. "main..HEAD" or
	// "<base sha>..<head sha>". This is the pull-request case: only what the
	// branch introduces is scanned, so a repository with pre-existing findings
	// can adopt Klarion without every PR failing on somebody else's leak.
	Range string
}

// rangeRe bounds what may be passed to git as a revision range. The value
// arrives from CI inputs (a branch name, a PR base SHA), so it is untrusted:
// this rejects anything that could be read as a flag or a shell word, leaving
// only the characters git revisions actually use.
var rangeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/@^~-]*(\.\.\.?[A-Za-z0-9][A-Za-z0-9._/@^~-]*)?$`)

// ValidateRange reports whether s is a syntactically acceptable revision range.
func ValidateRange(s string) error {
	if !rangeRe.MatchString(s) {
		return fmt.Errorf("invalid commit range %q: expected <rev> or <base>..<head> using [A-Za-z0-9._/@^~-]", s)
	}
	return nil
}

// MergeBase returns the common ancestor of two revisions. Pull requests are
// scanned from the merge base rather than the base branch tip: if the base
// branch has moved on since the branch was cut, a plain two-dot range would
// otherwise attribute other people's commits to this PR.
func MergeBase(ctx context.Context, dir, base, head string) (string, error) {
	if err := ValidateRange(base); err != nil {
		return "", err
	}
	if err := ValidateRange(head); err != nil {
		return "", err
	}
	out, err := run(ctx, dir, "merge-base", base, head)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// IsShallow reports whether dir is a shallow clone, whose history scan sees only
// the fetched commits. Errors (old git, not a repo) read as "not shallow".
func IsShallow(ctx context.Context, dir string) bool {
	out, err := run(ctx, dir, "rev-parse", "--is-shallow-repository")
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// HasRevision reports whether a revision is present in the local clone. CI
// often checks out a shallow tree, so the base commit of a pull request may
// simply not be there; callers use this to fall back to a full scan rather
// than fail.
func HasRevision(ctx context.Context, dir, rev string) bool {
	if err := ValidateRange(rev); err != nil {
		return false
	}
	_, err := run(ctx, dir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	return err == nil
}

// field/record separators for the machine-readable log format. They are ASCII
// control characters that never appear in commit metadata, so they parse
// unambiguously even when messages contain newlines or the default git
// delimiters.
const (
	fieldSep  = "\x1f" // US: between fields of one commit header
	recordSep = "\x1e" // RS: between commits
)

// ScanHistory walks commit history and returns the added lines of each commit,
// per file. We drive `git log -p` with -U0 (zero context) and --no-color so the
// unified-diff parser sees only markers and content, and with a custom
// --format so each commit is prefixed by a parseable header record.
//
// Without a Range it walks --all refs: a secret pushed on a feature branch, a
// tag or a stash is as leaked as one on main. Merge commits are included as
// dense combined diffs (--cc), which show only lines that differ from every
// parent -- a conflict resolution or an "evil merge" that introduces content no
// parent had. Lines a merge merely brings in from one side were already
// scanned in that side's own commits.
func ScanHistory(ctx context.Context, dir string, opts HistoryOptions) ([]HistoryHunk, error) {
	// The header is emitted as: RS hash US author US email US date US subject LF
	format := recordSep + "%H" + fieldSep + "%an" + fieldSep + "%ae" +
		fieldSep + "%ad" + fieldSep + "%s"
	args := []string{
		"log",
		"-p",
		"-U0",
		"--no-color",
		"--cc",
		"--date=iso-strict",
		"--format=" + format,
	}
	if opts.MaxCommits > 0 {
		args = append(args, fmt.Sprintf("-n%d", opts.MaxCommits))
	}
	if opts.Since != "" {
		args = append(args, "--since="+opts.Since)
	}
	if opts.Range != "" {
		if err := ValidateRange(opts.Range); err != nil {
			return nil, err
		}
		// "--" terminates option parsing: even though the range is validated,
		// a revision is data and must never be able to act as a flag.
		args = append(args, opts.Range, "--")
	} else {
		args = append(args, "--all")
	}
	out, err := run(ctx, dir, args...)
	if err != nil {
		return nil, err
	}
	return parseLog(string(out)), nil
}

// parseLog splits `git log -p` output on the record separator into per-commit
// chunks, extracts the header fields, and runs the diff parser over the body.
func parseLog(out string) []HistoryHunk {
	var hunks []HistoryHunk
	// The stream starts with a recordSep; each record is "header\nbody".
	records := strings.Split(out, recordSep)
	for _, rec := range records {
		rec = strings.TrimLeft(rec, "\n")
		if rec == "" {
			continue
		}
		// The header is the first line; the diff body is everything after it.
		header := rec
		body := ""
		if nl := strings.IndexByte(rec, '\n'); nl >= 0 {
			header = rec[:nl]
			body = rec[nl+1:]
		}
		fields := strings.Split(header, fieldSep)
		if len(fields) < 5 {
			continue
		}
		commit := Commit{
			Hash:    fields[0],
			Author:  fields[1],
			Email:   fields[2],
			Date:    fields[3],
			Message: fields[4],
		}
		for _, fd := range ParseUnifiedDiff(body) {
			hunks = append(hunks, HistoryHunk{
				Commit: commit,
				Path:   fd.Path,
				Lines:  fd.Added,
			})
		}
	}
	return hunks
}

// splitNUL splits git's -z output (NUL-terminated records) into a slice,
// dropping the trailing empty element after the final terminator.
func splitNUL(b []byte) []string {
	s := strings.TrimRight(string(b), "\x00")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

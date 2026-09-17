package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// newTestRepo creates an isolated git repository in a temp dir. It skips the
// test when git is unavailable, and scrubs the environment so the user's real
// git config / hooks / signing keys cannot influence (or break) the test.
func newTestRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	home := t.TempDir()

	// Hermetic environment: point HOME/config at throwaway dirs, disable global
	// and system config, and provide deterministic identity + no GPG signing.
	env := append(os.Environ(),
		"HOME="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=Klarion Test",
		"GIT_AUTHOR_EMAIL=test@klarion.dev",
		"GIT_COMMITTER_NAME=Klarion Test",
		"GIT_COMMITTER_EMAIL=test@klarion.dev",
		"GIT_TERMINAL_PROMPT=0",
	)
	gitEnv = env // used by the test-local git runner below

	gitInDir(t, dir, "init", "-q", "-b", "main")
	gitInDir(t, dir, "config", "user.name", "Klarion Test")
	gitInDir(t, dir, "config", "user.email", "test@klarion.dev")
	gitInDir(t, dir, "config", "commit.gpgsign", "false")
	return dir
}

// gitEnv holds the scrubbed environment shared with gitInDir; it is set per
// test by newTestRepo. Tests run serially within a package by default, and none
// of these run in parallel, so a package-level var is safe here.
var gitEnv []string

// gitInDir runs a git command in dir using the hermetic environment, failing
// the test on error. It mirrors the production run() but lets us inject env.
func gitInDir(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// withGitEnv runs fn with the process environment temporarily set to the
// hermetic env, so the production functions (which use the ambient env) behave
// deterministically. It restores the prior environment afterward.
func withGitEnv(t *testing.T, fn func()) {
	t.Helper()
	saved := map[string]string{}
	var unset []string
	apply := func(kv string) {
		i := strings.IndexByte(kv, '=')
		if i < 0 {
			return
		}
		k, v := kv[:i], kv[i+1:]
		if old, ok := os.LookupEnv(k); ok {
			if _, seen := saved[k]; !seen {
				saved[k] = old
			}
		} else {
			unset = append(unset, k)
		}
		os.Setenv(k, v)
	}
	for _, kv := range gitEnv {
		apply(kv)
	}
	defer func() {
		for k, v := range saved {
			os.Setenv(k, v)
		}
		for _, k := range unset {
			os.Unsetenv(k)
		}
	}()
	fn()
}

func TestIsRepoAndRoot(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	withGitEnv(t, func() {
		if !IsRepo(ctx, dir) {
			t.Errorf("IsRepo on a git repo = false, want true")
		}
		root, err := RepoRoot(ctx, dir)
		if err != nil {
			t.Fatalf("RepoRoot: %v", err)
		}
		// t.TempDir may live under a symlinked path (/var vs /private/var on
		// macOS); compare resolved forms.
		gotReal, _ := filepath.EvalSymlinks(root)
		wantReal, _ := filepath.EvalSymlinks(dir)
		if gotReal != wantReal {
			t.Errorf("RepoRoot = %q, want %q", gotReal, wantReal)
		}
	})

	// A plain temp dir with no repo must report false.
	plain := t.TempDir()
	withGitEnv(t, func() {
		if IsRepo(ctx, plain) {
			t.Errorf("IsRepo on non-repo = true, want false")
		}
	})
}

func TestStagedAndTrackedFiles(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	writeFile(t, dir, "committed.txt", "already here\n")
	gitInDir(t, dir, "add", "committed.txt")
	gitInDir(t, dir, "commit", "-q", "-m", "initial")

	// Stage a new file and a modification; leave a third file unstaged.
	writeFile(t, dir, "staged.txt", "SECRET=abc123\n")
	writeFile(t, dir, "committed.txt", "already here\nmore\n")
	writeFile(t, dir, "unstaged.txt", "not added\n")
	gitInDir(t, dir, "add", "staged.txt", "committed.txt")

	withGitEnv(t, func() {
		staged, err := StagedFiles(ctx, dir)
		if err != nil {
			t.Fatalf("StagedFiles: %v", err)
		}
		got := map[string]string{}
		for _, f := range staged {
			got[f.Path] = string(f.Content)
		}
		if _, ok := got["unstaged.txt"]; ok {
			t.Errorf("unstaged.txt should not be staged: %v", got)
		}
		if v := got["staged.txt"]; v != "SECRET=abc123\n" {
			t.Errorf("staged.txt content = %q, want the staged blob", v)
		}
		if v := got["committed.txt"]; v != "already here\nmore\n" {
			t.Errorf("committed.txt staged content = %q", v)
		}

		tracked, err := TrackedFiles(ctx, dir)
		if err != nil {
			t.Fatalf("TrackedFiles: %v", err)
		}
		set := map[string]bool{}
		for _, p := range tracked {
			set[p] = true
		}
		if !set["committed.txt"] || !set["staged.txt"] {
			t.Errorf("TrackedFiles = %v, want committed.txt and staged.txt", tracked)
		}
		if set["unstaged.txt"] {
			t.Errorf("unstaged.txt is not tracked yet but appeared in %v", tracked)
		}
	})
}

func TestStagedContentUsesIndexNotWorktree(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	writeFile(t, dir, "f.txt", "staged version\n")
	gitInDir(t, dir, "add", "f.txt")
	// Change the working tree after staging: StagedFiles must return the
	// *staged* blob, not this newer content.
	writeFile(t, dir, "f.txt", "worktree version\n")

	withGitEnv(t, func() {
		staged, err := StagedFiles(ctx, dir)
		if err != nil {
			t.Fatalf("StagedFiles: %v", err)
		}
		if len(staged) != 1 || staged[0].Path != "f.txt" {
			t.Fatalf("StagedFiles = %+v, want single f.txt", staged)
		}
		if string(staged[0].Content) != "staged version\n" {
			t.Errorf("content = %q, want the staged (index) blob", staged[0].Content)
		}
	})
}

func TestScanHistory(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	writeFile(t, dir, "a.txt", "first line\n")
	gitInDir(t, dir, "add", "a.txt")
	gitInDir(t, dir, "commit", "-q", "-m", "add a")

	writeFile(t, dir, "a.txt", "first line\nAPI_KEY=sk-live-999\n")
	gitInDir(t, dir, "add", "a.txt")
	gitInDir(t, dir, "commit", "-q", "-m", "add secret")

	withGitEnv(t, func() {
		hunks, err := ScanHistory(ctx, dir, HistoryOptions{})
		if err != nil {
			t.Fatalf("ScanHistory: %v", err)
		}
		var foundSecret, foundFirst bool
		for _, h := range hunks {
			if h.Path != "a.txt" {
				t.Errorf("unexpected path %q", h.Path)
			}
			if h.Commit.Email != "test@klarion.dev" {
				t.Errorf("commit email = %q", h.Commit.Email)
			}
			for _, ln := range h.Lines {
				if ln.Text == "API_KEY=sk-live-999" {
					foundSecret = true
					if ln.Number != 2 {
						t.Errorf("secret line number = %d, want 2", ln.Number)
					}
				}
				if ln.Text == "first line" {
					foundFirst = true
				}
			}
		}
		if !foundSecret {
			t.Errorf("did not find the introduced secret in history: %+v", hunks)
		}
		if !foundFirst {
			t.Errorf("did not find the first commit's added line: %+v", hunks)
		}
	})

	// MaxCommits=1 must restrict the walk to the newest commit only.
	withGitEnv(t, func() {
		hunks, err := ScanHistory(ctx, dir, HistoryOptions{MaxCommits: 1})
		if err != nil {
			t.Fatalf("ScanHistory(MaxCommits=1): %v", err)
		}
		for _, h := range hunks {
			for _, ln := range h.Lines {
				if ln.Text == "first line" {
					t.Errorf("MaxCommits=1 leaked an older commit's line: %+v", hunks)
				}
			}
		}
	})
}

// TestParseLog exercises the header-parsing path without invoking git, so it
// runs even when git is absent.
func TestParseLog(t *testing.T) {
	out := recordSep + "deadbeef" + fieldSep + "Ada" + fieldSep +
		"ada@example.com" + fieldSep + "2026-07-07T00:00:00Z" + fieldSep +
		"do a thing\n" +
		"diff --git a/x.txt b/x.txt\n" +
		"--- a/x.txt\n" +
		"+++ b/x.txt\n" +
		"@@ -0,0 +1 @@\n" +
		"+hello\n"

	hunks := parseLog(out)
	if len(hunks) != 1 {
		t.Fatalf("parseLog got %d hunks, want 1: %+v", len(hunks), hunks)
	}
	h := hunks[0]
	if h.Commit.Hash != "deadbeef" || h.Commit.Author != "Ada" ||
		h.Commit.Email != "ada@example.com" || h.Commit.Message != "do a thing" {
		t.Errorf("commit header parsed wrong: %+v", h.Commit)
	}
	if h.Path != "x.txt" || len(h.Lines) != 1 || h.Lines[0].Text != "hello" ||
		h.Lines[0].Number != 1 {
		t.Errorf("hunk body parsed wrong: %+v", h)
	}
}

func TestSplitNUL(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a\x00", []string{"a"}},
		{"a\x00b\x00", []string{"a", "b"}},
		{"a\x00b", []string{"a", "b"}},
	}
	for _, tt := range tests {
		got := splitNUL([]byte(tt.in))
		if len(got) != len(tt.want) {
			t.Errorf("splitNUL(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitNUL(%q)[%d] = %q, want %q", tt.in, i, got[i], tt.want[i])
			}
		}
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// A repository that sets core.hooksPath (husky, pre-commit, corporate
// templates) makes git ignore .git/hooks entirely. Installing there would
// report success and protect nothing, so HooksDir must follow the config.
func TestHooksDirHonorsCoreHooksPath(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	withGitEnv(t, func() {
		root, err := RepoRoot(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}

		got, err := HooksDir(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(root, ".git", "hooks"); got != want {
			t.Errorf("default HooksDir = %q, want %q", got, want)
		}

		gitInDir(t, dir, "config", "core.hooksPath", ".husky")
		got, err = HooksDir(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(root, ".husky"); got != want {
			t.Errorf("relative core.hooksPath: HooksDir = %q, want %q", got, want)
		}

		abs := filepath.Join(t.TempDir(), "shared-hooks")
		gitInDir(t, dir, "config", "core.hooksPath", abs)
		got, err = HooksDir(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		if got != abs {
			t.Errorf("absolute core.hooksPath: HooksDir = %q, want %q", got, abs)
		}
	})
}

// Range scanning is the pull-request path: a branch is judged on what it adds,
// not on what was already in the repository.
func TestScanHistoryRange(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	withGitEnv(t, func() {
		write := func(name, body string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			gitInDir(t, dir, "add", name)
		}

		write("old.txt", "old_key = AKIAOLDOLDOLDOLDOLD1\n")
		gitInDir(t, dir, "commit", "-m", "pre-existing")
		base := strings.TrimSpace(gitInDir(t, dir, "rev-parse", "HEAD"))

		gitInDir(t, dir, "checkout", "-b", "feature")
		write("new.txt", "new_key = AKIANEWNEWNEWNEWNEW2\n")
		gitInDir(t, dir, "commit", "-m", "branch work")

		// Whole history sees both commits.
		all, err := ScanHistory(ctx, dir, HistoryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if got := hunkPaths(all); len(got) != 2 {
			t.Errorf("full history hunks = %v, want both files", got)
		}

		// The range sees only what the branch added.
		ranged, err := ScanHistory(ctx, dir, HistoryOptions{Range: base + "..HEAD"})
		if err != nil {
			t.Fatal(err)
		}
		got := hunkPaths(ranged)
		if len(got) != 1 || got[0] != "new.txt" {
			t.Errorf("range hunks = %v, want [new.txt]", got)
		}
	})
}

func hunkPaths(hs []HistoryHunk) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Path)
	}
	sort.Strings(out)
	return out
}

// MergeBase is what stops a moving base branch from being blamed on a PR.
func TestMergeBaseIgnoresLaterBaseCommits(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()

	withGitEnv(t, func() {
		write := func(name, body string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			gitInDir(t, dir, "add", name)
		}
		write("a.txt", "start\n")
		gitInDir(t, dir, "commit", "-m", "root")
		root := strings.TrimSpace(gitInDir(t, dir, "rev-parse", "HEAD"))
		mainBranch := strings.TrimSpace(gitInDir(t, dir, "rev-parse", "--abbrev-ref", "HEAD"))

		gitInDir(t, dir, "checkout", "-b", "feature")
		write("feature.txt", "feature_key = AKIAFEATUREFEATURE01\n")
		gitInDir(t, dir, "commit", "-m", "feature work")

		// The base branch moves on with a leak of its own.
		gitInDir(t, dir, "checkout", mainBranch)
		write("later.txt", "main_key = AKIALATERLATERLATER1\n")
		gitInDir(t, dir, "commit", "-m", "leak on main after the branch was cut")
		gitInDir(t, dir, "checkout", "feature")

		mb, err := MergeBase(ctx, dir, mainBranch, "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		if mb != root {
			t.Fatalf("MergeBase = %s, want the root commit %s", mb, root)
		}

		hunks, err := ScanHistory(ctx, dir, HistoryOptions{Range: mb + "..HEAD"})
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range hunkPaths(hunks) {
			if p == "later.txt" {
				t.Error("a commit made on the base branch after the cut was attributed to this branch")
			}
		}
	})
}

// A range arrives from CI inputs, so it is untrusted: it must never be able to
// act as a git flag or carry shell metacharacters.
func TestValidateRange(t *testing.T) {
	valid := []string{
		"main", "HEAD", "v1.2.3", "feature/thing", "abc123..def456",
		"main...HEAD", "HEAD~3", "origin/main..HEAD", "HEAD^",
	}
	for _, v := range valid {
		if err := ValidateRange(v); err != nil {
			t.Errorf("ValidateRange(%q) = %v, want nil", v, err)
		}
	}
	invalid := []string{
		"--upload-pack=touch /tmp/pwned", "-n1", "main; rm -rf /",
		"main$(whoami)", "main`id`", "main|cat", "", "main HEAD",
		"--all", "..main", "main&&id", "$(id)", "main\nrm",
	}
	for _, v := range invalid {
		if err := ValidateRange(v); err == nil {
			t.Errorf("ValidateRange(%q) = nil, want an error", v)
		}
	}
}

func TestHasRevision(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()
	withGitEnv(t, func() {
		if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		gitInDir(t, dir, "add", "f.txt")
		gitInDir(t, dir, "commit", "-m", "c")

		if !HasRevision(ctx, dir, "HEAD") {
			t.Error("HEAD should exist")
		}
		if HasRevision(ctx, dir, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") {
			t.Error("a random sha should not exist")
		}
		if HasRevision(ctx, dir, "--all") {
			t.Error("a flag-shaped revision must be rejected before reaching git")
		}
	})
}

// History means every ref: a leak on an unmerged branch is pushed and public,
// and a merge can introduce content neither parent had.
func TestScanHistoryAllRefsAndMerges(t *testing.T) {
	dir := newTestRepo(t)
	ctx := context.Background()
	commit := func(msg string) { gitInDir(t, dir, "commit", "-q", "-am", msg) }

	writeFile(t, dir, "a.txt", "base\n")
	gitInDir(t, dir, "add", "a.txt")
	commit("base")

	gitInDir(t, dir, "checkout", "-q", "-b", "leak")
	writeFile(t, dir, "b.txt", "password = branch-only-leak\n")
	gitInDir(t, dir, "add", "b.txt")
	commit("unmerged branch")
	gitInDir(t, dir, "checkout", "-q", "main")

	gitInDir(t, dir, "checkout", "-q", "-b", "side")
	writeFile(t, dir, "a.txt", "side\n")
	commit("side")
	gitInDir(t, dir, "checkout", "-q", "main")
	writeFile(t, dir, "a.txt", "main\n")
	commit("main")
	merge := exec.Command("git", "merge", "-q", "side")
	merge.Dir, merge.Env = dir, gitEnv
	_ = merge.Run() // conflicts by design
	writeFile(t, dir, "a.txt", "main\nside\nevil = merged-in-resolution\n")
	gitInDir(t, dir, "add", "a.txt")
	gitInDir(t, dir, "commit", "-q", "-m", "merge side")

	withGitEnv(t, func() {
		hunks, err := ScanHistory(ctx, dir, HistoryOptions{})
		if err != nil {
			t.Fatal(err)
		}
		var branchLeak bool
		var mergeLines []string
		for _, h := range hunks {
			for _, ln := range h.Lines {
				branchLeak = branchLeak || ln.Text == "password = branch-only-leak"
				if h.Commit.Message == "merge side" {
					mergeLines = append(mergeLines, ln.Text)
				}
			}
		}
		if !branchLeak {
			t.Error("history scan missed a commit that exists only on another branch")
		}
		if len(mergeLines) != 1 || mergeLines[0] != "evil = merged-in-resolution" {
			t.Errorf("merge commit lines = %q, want only the line no parent had", mergeLines)
		}
		if IsShallow(ctx, dir) {
			t.Error("full clone reported shallow")
		}
	})

	shallow := filepath.Join(t.TempDir(), "shallow")
	gitInDir(t, t.TempDir(), "clone", "-q", "--depth", "1", "file://"+dir, shallow)
	withGitEnv(t, func() {
		if !IsShallow(ctx, shallow) {
			t.Error("depth-1 clone not reported shallow")
		}
	})
}

// UncommittedChanges must cover everything a `git add -A && git commit` could
// put into the next commit, and nothing already committed or ignored.
func TestUncommittedChanges(t *testing.T) {
	dir := newTestRepo(t)
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	withGitEnv(t, func() {
		ctx := context.Background()

		// Before the first commit: a staged file must still show up.
		write("first.txt", "alpha\n")
		gitInDir(t, dir, "add", "first.txt")
		diffs, untracked, err := UncommittedChanges(ctx, dir)
		if err != nil {
			t.Fatalf("unborn branch: %v", err)
		}
		if len(diffs) != 1 || diffs[0].Path != "first.txt" || len(untracked) != 0 {
			t.Fatalf("unborn branch: diffs=%+v untracked=%v", diffs, untracked)
		}
		gitInDir(t, dir, "commit", "-q", "-m", "first")

		write(".gitignore", "ignored.txt\n")
		write("tracked.txt", "old line\n")
		gitInDir(t, dir, "add", ".gitignore", "tracked.txt")
		gitInDir(t, dir, "commit", "-q", "-m", "second")

		write("tracked.txt", "old line\nunstaged line\n") // tracked, not staged
		write("staged.txt", "staged line\n")
		gitInDir(t, dir, "add", "staged.txt")
		write("sub/new.txt", "untracked\n")
		write("ignored.txt", "ignored\n")

		diffs, untracked, err = UncommittedChanges(ctx, dir)
		if err != nil {
			t.Fatal(err)
		}
		added := map[string][]string{}
		for _, d := range diffs {
			for _, l := range d.Added {
				added[d.Path] = append(added[d.Path], l.Text)
			}
		}
		if got := added["tracked.txt"]; len(got) != 1 || got[0] != "unstaged line" {
			t.Errorf("tracked.txt added lines = %q, want only the new line", got)
		}
		if got := added["staged.txt"]; len(got) != 1 || got[0] != "staged line" {
			t.Errorf("staged.txt added lines = %q", got)
		}
		if _, ok := added["first.txt"]; ok {
			t.Error("already committed file reported as a change")
		}
		sort.Strings(untracked)
		if strings.Join(untracked, ",") != "sub/new.txt" {
			t.Errorf("untracked = %v, want [sub/new.txt] (ignored.txt excluded)", untracked)
		}
	})
}

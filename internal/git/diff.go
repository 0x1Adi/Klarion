// Package git integrates Klarion with the local git repository: staged-file
// scanning for pre-commit hooks and full-history scanning for audits. It shells
// out to the `git` binary rather than linking a git library so behaviour tracks
// the user's actual git exactly (config, attributes, ignore rules).
package git

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/0x1Adi/Klarion/internal/detect"
)

// FileDiff is the added content of a single file within a unified diff. Only
// added lines matter to Klarion: a secret introduced by a commit lives on a '+'
// line, and its new-file line number is what a reviewer needs to jump to.
type FileDiff struct {
	Path  string
	Added []detect.Line
}

// hunkHeaderRe captures the new-file start line (group 1) of a hunk header:
//
//	@@ -oldStart,oldCount +newStart,newCount @@ optional section heading
//
// The old-side numbers and the counts are irrelevant to us; we re-derive
// positions by walking the body line by line.
var hunkHeaderRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// combinedHeaderRe captures a combined-diff hunk header for a merge with N
// parents: N+1 '@', one -old range per parent, then the +new range.
//
//	@@@ -1,2 -1,2 +1,3 @@@
var combinedHeaderRe = regexp.MustCompile(`^(@{3,}) (?:-\d+(?:,\d+)? )+\+(\d+)(?:,\d+)? @{3,}`)

// ParseUnifiedDiff parses `git diff`/`git log -p` output into per-file added
// lines. It is deliberately tolerant: git emits several path-declaration forms
// (rename, new/deleted file, mode changes) and interleaves them with hunks, so
// we track the "current file" across the stream and reset the line counter at
// each hunk header.
//
// Binary diffs ("Binary files a/x and b/y differ" or "GIT binary patch") carry
// no line content and are skipped — Klarion never scans binary blobs.
func ParseUnifiedDiff(diff string) []FileDiff {
	var files []FileDiff
	var cur *FileDiff // the file whose hunks we are currently accumulating
	newLine := 0      // next new-file line number to assign
	inHunk := false   // whether we are inside a hunk body
	binary := false   // current file is binary; drop its (empty) diff
	parents := 1      // marker columns per body line: 1, or N for a merge's combined diff

	// flush commits the in-progress file to the result unless it is binary or
	// produced no added lines (pure deletions, mode-only changes, renames).
	flush := func() {
		if cur != nil && !binary && len(cur.Added) > 0 {
			files = append(files, *cur)
		}
		cur = nil
		binary = false
		inHunk = false
		newLine = 0
	}

	// start begins a new file, flushing any predecessor first.
	start := func(path string) {
		flush()
		cur = &FileDiff{Path: path}
	}

	lines := strings.Split(diff, "\n")
	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, "diff --cc "), strings.HasPrefix(line, "diff --combined "):
			// Merge commit (--cc). The header names the result path directly.
			start(line[strings.IndexByte(line[5:], ' ')+6:])

		case strings.HasPrefix(line, "diff --git "):
			// New file section. Derive a provisional path from the header; the
			// authoritative path is refined by a later +++/rename line, but the
			// header covers the common a/x b/x case and pure-rename diffs that
			// carry no +++ line.
			if p, ok := pathFromDiffGit(line); ok {
				start(p)
			} else {
				start("")
			}

		case strings.HasPrefix(line, "Binary files "),
			strings.HasPrefix(line, "GIT binary patch"):
			binary = true

		case strings.HasPrefix(line, "rename to "):
			// A rename with no content change still names the file; prefer it.
			if cur != nil {
				cur.Path = strings.TrimPrefix(line, "rename to ")
			}

		case strings.HasPrefix(line, "+++ "):
			// The definitive new-side path. "/dev/null" means the file was
			// deleted, so there is nothing to add.
			p := strings.TrimPrefix(line, "+++ ")
			p = trimDiffTimestamp(p)
			if p == "/dev/null" {
				continue
			}
			p = strings.TrimPrefix(p, "b/")
			if cur == nil {
				cur = &FileDiff{}
			}
			if p != "" {
				cur.Path = p
			}

		case strings.HasPrefix(line, "--- "):
			// Old-side header; ignored, but must not be mistaken for a '-' body
			// line, so it is handled here before the '-' case below.

		case strings.HasPrefix(line, "@@"):
			startLine, cols := "", 1
			if m := combinedHeaderRe.FindStringSubmatch(line); m != nil {
				startLine, cols = m[2], len(m[1])-1
			} else if m := hunkHeaderRe.FindStringSubmatch(line); m != nil {
				startLine = m[1]
			}
			n, err := strconv.Atoi(startLine)
			if err != nil {
				inHunk = false
				continue
			}
			newLine, parents = n, cols
			inHunk = true

		case inHunk && parents > 1:
			// Combined diff: one marker column per parent. A '-' in any column
			// means the line is not in the merge result. All '+' means the merge
			// itself introduced it; that is the only content no parent's own
			// commits already contributed.
			if len(line) < parents || strings.ContainsRune(line[:parents], '-') {
				continue
			}
			if strings.Count(line[:parents], "+") == parents && cur != nil {
				cur.Added = append(cur.Added, detect.Line{Number: newLine, Text: line[parents:]})
			}
			newLine++

		case !inHunk:
			// Metadata line (index, mode, similarity, commit prose, etc.).
			continue

		default:
			// Inside a hunk body. Classify by the leading marker column.
			if line == "" {
				// A blank line in the stream is an empty context line; it maps
				// to a new-file line and advances the counter.
				newLine++
				continue
			}
			switch line[0] {
			case '+':
				if cur != nil {
					cur.Added = append(cur.Added, detect.Line{
						Number: newLine,
						Text:   line[1:],
					})
				}
				newLine++
			case '-':
				// Removed line: exists only on the old side; do not advance.
			case '\\':
				// "\ No newline at end of file" — not a real line.
			default:
				// Context line (leading space) or anything else: advances the
				// new-file counter without being scanned.
				newLine++
			}
		}
	}
	flush()
	return files
}

// pathFromDiffGit extracts the file path from a "diff --git a/x b/y" line. When
// the two sides differ (rename/copy) it returns the b-side. Paths containing
// spaces make this ambiguous in the general case; we handle the common
// unambiguous form and let a subsequent +++/rename line correct the rest.
func pathFromDiffGit(line string) (string, bool) {
	rest := strings.TrimPrefix(line, "diff --git ")
	// Find " b/" as the separator between the a-side and b-side.
	idx := strings.Index(rest, " b/")
	if idx < 0 {
		return "", false
	}
	b := rest[idx+len(" b/"):]
	if b == "" {
		return "", false
	}
	return b, true
}

// trimDiffTimestamp strips the optional tab-separated timestamp that plain
// `diff -u` (and some git configs) append to file headers.
func trimDiffTimestamp(p string) string {
	if i := strings.IndexByte(p, '\t'); i >= 0 {
		return p[:i]
	}
	return p
}

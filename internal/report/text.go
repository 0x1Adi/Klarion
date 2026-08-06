package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// textReporter renders a human-readable report grouped by file. It emits no
// ANSI escapes itself: color is the caller's job (it may wrap w to add or strip
// escapes), which keeps this output deterministic and testable.
type textReporter struct {
	redact         bool
	showSuppressed bool
}

func (t *textReporter) Write(w io.Writer, r Result) error {
	bw := &errWriter{w: w}

	if len(r.Findings) == 0 && !(t.showSuppressed && len(r.Suppressed) > 0) {
		bw.printf("No secrets detected (%d files scanned).\n", r.FilesScanned)
	} else {
		t.writeGroup(bw, r.Findings)
		if t.showSuppressed && len(r.Suppressed) > 0 {
			bw.printf("\nSuppressed:\n")
			t.writeGroup(bw, r.Suppressed)
		}
	}

	// Summary line last so it is easy to grep and always present.
	bw.printf("\nSummary: %d finding(s) across %d file(s), %d suppressed [%d files scanned in %s]\n",
		len(r.Findings), fileCount(r.Findings), len(r.Suppressed), r.FilesScanned, r.Duration.Round(1e6))
	return bw.err
}

// writeGroup prints findings grouped and sorted by file, then by line, so the
// output is stable regardless of scan/goroutine ordering.
func (t *textReporter) writeGroup(bw *errWriter, findings []finding.Finding) {
	byFile := map[string][]finding.Finding{}
	var files []string
	for _, f := range findings {
		if _, ok := byFile[f.FilePath]; !ok {
			files = append(files, f.FilePath)
		}
		byFile[f.FilePath] = append(byFile[f.FilePath], f)
	}
	sort.Strings(files)

	for _, file := range files {
		fs := byFile[file]
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].Line < fs[j].Line })
		bw.printf("\n%s\n", file)
		for _, f := range fs {
			col := f.Column
			bw.printf("  [%s] %s  %d:%d  %s\n",
				f.Severity, f.RuleID, f.Line, col, secretForDisplay(f, t.redact))
			// Verdict + confidence tells the reader whether AI adjudicated it.
			if c := f.Verdict.Confidence; c > 0 {
				bw.printf("    verdict: %s (confidence %.2f)\n", verdictLabel(f.Verdict), c)
			} else {
				bw.printf("    verdict: %s\n", verdictLabel(f.Verdict))
			}
			if snippet := t.snippet(f); snippet != "" {
				bw.printf("    | %s\n", snippet)
			}
		}
	}
}

// snippet returns the single-line context for a finding, preferring the raw
// line and falling back to the AI context blob's first line.
func (t *textReporter) snippet(f finding.Finding) string {
	text := f.LineText
	if text == "" {
		text = firstLine(f.Context)
	}
	if text == "" {
		return ""
	}
	return contextForDisplay(text, f, t.redact)
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// errWriter defers write-error handling so the format code stays linear; the
// first error is remembered and returned by Write.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) printf(format string, a ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, a...)
}

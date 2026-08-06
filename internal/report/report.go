// Package report renders scan results in the formats CI systems and humans
// consume: a colorless human report, stable JSON, SARIF 2.1.0 (code scanning),
// JUnit XML (generic CI), and the GitLab Secret Detection schema.
//
// Every reporter takes a plain io.Writer so the caller owns terminal concerns
// (TTY detection, color, paging); a reporter never inspects the writer. The
// redact flag decides whether raw secrets may appear in output — it defaults on
// and is only turned off deliberately (e.g. `--no-redact` for local triage).
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// Result is the full outcome of a scan handed to a Reporter. Findings are the
// active (failing) hits; Suppressed were demoted by baseline/allowlist/AI and
// are only rendered when the reporter is asked to show them.
type Result struct {
	Findings     []finding.Finding
	Suppressed   []finding.Finding
	FilesScanned int
	Duration     time.Duration
	Tool         string
	Version      string
}

// Reporter serializes a Result to w. Implementations must be safe to reuse and
// must not close w (the caller owns it).
type Reporter interface {
	Write(w io.Writer, r Result) error
}

// New builds a Reporter for the named format. redact hides raw secrets;
// showSuppressed includes baseline/AI-suppressed findings in the output.
func New(format string, redact, showSuppressed bool) (Reporter, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		return &textReporter{redact: redact, showSuppressed: showSuppressed}, nil
	case "json":
		return &jsonReporter{redact: redact}, nil
	case "sarif":
		return &sarifReporter{redact: redact, showSuppressed: showSuppressed}, nil
	case "junit":
		return &junitReporter{redact: redact, showSuppressed: showSuppressed}, nil
	case "gitlab":
		return &gitlabReporter{redact: redact}, nil
	default:
		return nil, fmt.Errorf("report: unknown format %q (want text|json|sarif|junit|gitlab)", format)
	}
}

// secretForDisplay returns the value to show for a finding's secret: the
// redacted form when redacting, otherwise the raw secret (falling back to the
// redacted form if the raw value was never captured).
func secretForDisplay(f finding.Finding, redact bool) string {
	if redact {
		if f.Redacted != "" {
			return f.Redacted
		}
		return finding.Redact(f.Secret)
	}
	if f.Secret != "" {
		return f.Secret
	}
	return f.Redacted
}

// contextForDisplay sanitizes a context/line snippet: when redacting, every
// occurrence of the raw secret inside text is masked so context never leaks it.
func contextForDisplay(text string, f finding.Finding, redact bool) string {
	if redact {
		return finding.RedactInText(text, f.Secret)
	}
	return text
}

// verdictLabel is the human/report label for a finding's verdict; an empty
// status means the verifier never ran.
func verdictLabel(v finding.Verdict) string {
	if v.Status == "" {
		return string(finding.VerdictUnverified)
	}
	return string(v.Status)
}

// fileCount returns the number of distinct files touched by findings.
func fileCount(fs []finding.Finding) int {
	seen := make(map[string]struct{}, len(fs))
	for _, f := range fs {
		seen[f.FilePath] = struct{}{}
	}
	return len(seen)
}

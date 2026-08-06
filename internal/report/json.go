package report

import (
	"encoding/json"
	"io"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// jsonReporter emits stable machine JSON. finding.Finding already carries json
// tags and tags its raw Secret/LineText/Context as `-`, so those never leak
// through the normal path. The only way a raw secret enters the document is the
// explicit, opt-in "secret" field added when redaction is disabled.
type jsonReporter struct {
	redact bool
}

// findingView augments a Finding with an optional raw secret without mutating
// the finding. The embedded Secret field (json:"-") is shadowed by this
// shallower Secret field, so encoding/json uses ours: empty (omitted) when
// redacting, populated only when the caller explicitly disabled redaction.
type findingView struct {
	finding.Finding
	Secret string `json:"secret,omitempty"`
}

type jsonReport struct {
	Tool         string        `json:"tool"`
	Version      string        `json:"version"`
	FilesScanned int           `json:"files_scanned"`
	DurationMS   int64         `json:"duration_ms"`
	Findings     []findingView `json:"findings"`
	Suppressed   []findingView `json:"suppressed"`
	Summary      jsonSummary   `json:"summary"`
}

type jsonSummary struct {
	Total      int            `json:"total"`
	Files      int            `json:"files"`
	Suppressed int            `json:"suppressed"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	ByVerdict  map[string]int `json:"by_verdict,omitempty"`
}

func (j *jsonReporter) Write(w io.Writer, r Result) error {
	doc := jsonReport{
		Tool:         r.Tool,
		Version:      r.Version,
		FilesScanned: r.FilesScanned,
		DurationMS:   r.Duration.Milliseconds(),
		Findings:     j.views(r.Findings),
		Suppressed:   j.views(r.Suppressed),
		Summary: jsonSummary{
			Total:      len(r.Findings),
			Files:      fileCount(r.Findings),
			Suppressed: len(r.Suppressed),
			BySeverity: countBy(r.Findings, func(f finding.Finding) string { return string(f.Severity) }),
			ByVerdict:  countBy(r.Findings, func(f finding.Finding) string { return verdictLabel(f.Verdict) }),
		},
	}
	// Always allocate empty slices, never null, so consumers can iterate safely.
	if doc.Findings == nil {
		doc.Findings = []findingView{}
	}
	if doc.Suppressed == nil {
		doc.Suppressed = []findingView{}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func (j *jsonReporter) views(fs []finding.Finding) []findingView {
	if len(fs) == 0 {
		return nil
	}
	out := make([]findingView, len(fs))
	for i, f := range fs {
		v := findingView{Finding: f}
		if !j.redact {
			v.Secret = f.Secret
		}
		out[i] = v
	}
	return out
}

func countBy(fs []finding.Finding, key func(finding.Finding) string) map[string]int {
	if len(fs) == 0 {
		return nil
	}
	m := map[string]int{}
	for _, f := range fs {
		m[key(f)]++
	}
	return m
}

package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// gitlabReporter emits the GitLab Secret Detection report schema (v15.0.0) so
// findings appear on merge requests and the security dashboard. Only active
// findings are reported as vulnerabilities; suppressed ones are, by definition,
// not vulnerabilities GitLab should surface.
type gitlabReporter struct {
	redact bool
}

type gitlabReport struct {
	Version         string       `json:"version"`
	Scan            gitlabScan   `json:"scan"`
	Vulnerabilities []gitlabVuln `json:"vulnerabilities"`
}

type gitlabScan struct {
	Analyzer  gitlabTool `json:"analyzer"`
	Scanner   gitlabTool `json:"scanner"`
	Type      string     `json:"type"`
	StartTime string     `json:"start_time"`
	EndTime   string     `json:"end_time"`
	Status    string     `json:"status"`
}

type gitlabTool struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Vendor  gitlabVendor `json:"vendor"`
}

type gitlabVendor struct {
	Name string `json:"name"`
}

type gitlabVuln struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Name        string             `json:"name"`
	Message     string             `json:"message"`
	Description string             `json:"description,omitempty"`
	CVE         string             `json:"cve"`
	Severity    string             `json:"severity"`
	Location    gitlabLocation     `json:"location"`
	Identifiers []gitlabIdentifier `json:"identifiers"`
}

type gitlabLocation struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
}

type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (g *gitlabReporter) Write(w io.Writer, r Result) error {
	// GitLab requires an ISO-8601 window; derive the start from the duration.
	end := time.Now().UTC()
	start := end.Add(-r.Duration)
	const isoLocal = "2006-01-02T15:04:05" // GitLab schema forbids a timezone suffix

	tool := gitlabTool{
		ID:      "klarion",
		Name:    "Klarion",
		Version: nonEmpty(r.Version, "0.0.0"),
		Vendor:  gitlabVendor{Name: "Klarion"},
	}

	vulns := make([]gitlabVuln, 0, len(r.Findings))
	for _, f := range r.Findings {
		vulns = append(vulns, gitlabVuln{
			ID:          nonEmpty(f.Fingerprint, f.ComputeFingerprint()),
			Category:    "secret_detection",
			Name:        descOrID(f),
			Message:     descOrID(f),
			Description: gitlabDescription(f, g.redact),
			CVE:         nonEmpty(f.Fingerprint, f.ComputeFingerprint()),
			Severity:    gitlabSeverity(f.Severity),
			Location: gitlabLocation{
				File:      f.FilePath,
				StartLine: maxInt(f.Line, 1),
			},
			Identifiers: []gitlabIdentifier{{
				Type:  "klarion_rule_id",
				Name:  "Klarion rule " + f.RuleID,
				Value: f.RuleID,
			}},
		})
	}

	report := gitlabReport{
		Version: "15.0.0",
		Scan: gitlabScan{
			Analyzer:  tool,
			Scanner:   tool,
			Type:      "secret_detection",
			StartTime: start.Format(isoLocal),
			EndTime:   end.Format(isoLocal),
			Status:    "success",
		},
		Vulnerabilities: vulns,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

// gitlabSeverity maps to GitLab's capitalized severity vocabulary.
func gitlabSeverity(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical:
		return "Critical"
	case finding.SeverityHigh:
		return "High"
	case finding.SeverityMedium:
		return "Medium"
	case finding.SeverityLow:
		return "Low"
	default:
		return "Unknown"
	}
}

func gitlabDescription(f finding.Finding, redact bool) string {
	return descOrID(f) + " [" + verdictLabel(f.Verdict) + "]: " + secretForDisplay(f, redact)
}

func nonEmpty(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

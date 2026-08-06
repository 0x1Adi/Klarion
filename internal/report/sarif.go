package report

import (
	"encoding/json"
	"io"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// sarifSchemaURI is the canonical SARIF 2.1.0 schema; code-scanning ingesters
// (GitHub, Azure DevOps) key off this exact value.
const sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"

// sarifReporter emits SARIF 2.1.0. Each finding becomes a result; suppressed
// findings are still emitted (when asked) but carry a suppressions array so the
// UI shows them as dismissed rather than active alerts.
type sarifReporter struct {
	redact         bool
	showSuppressed bool
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription sarifText      `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	RuleIndex           int                `json:"ruleIndex"`
	Level               string             `json:"level"`
	Message             sarifText          `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type sarifSuppression struct {
	Kind string `json:"kind"` // "external" — suppressed outside the SARIF file (baseline/AI)
}

func (s *sarifReporter) Write(w io.Writer, r Result) error {
	// Emit active findings, then suppressed ones (flagged) when requested.
	emitted := make([]sarifFinding, 0, len(r.Findings)+len(r.Suppressed))
	for _, f := range r.Findings {
		emitted = append(emitted, sarifFinding{f, false})
	}
	if s.showSuppressed {
		for _, f := range r.Suppressed {
			emitted = append(emitted, sarifFinding{f, true})
		}
	}

	// Build a stable, deduplicated rule table and rule->index map.
	ruleIndex := map[string]int{}
	var rules []sarifRule
	for _, ef := range emitted {
		if _, ok := ruleIndex[ef.f.RuleID]; ok {
			continue
		}
		ruleIndex[ef.f.RuleID] = len(rules)
		rules = append(rules, sarifRule{
			ID:               ef.f.RuleID,
			Name:             ef.f.RuleID,
			ShortDescription: sarifText{Text: descOrID(ef.f)},
		})
	}
	if rules == nil {
		rules = []sarifRule{}
	}

	results := make([]sarifResult, 0, len(emitted))
	for _, ef := range emitted {
		res := sarifResult{
			RuleID:    ef.f.RuleID,
			RuleIndex: ruleIndex[ef.f.RuleID],
			Level:     sarifLevel(ef.f.Severity),
			Message:   sarifText{Text: sarifMessage(ef.f, s.redact)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: ef.f.FilePath},
					Region: sarifRegion{
						StartLine:   maxInt(ef.f.Line, 1),
						StartColumn: ef.f.Column,
						EndColumn:   ef.f.EndColumn,
					},
				},
			}},
		}
		if ef.f.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"klarion/v1": ef.f.Fingerprint}
		}
		if ef.suppressed {
			res.Suppressions = []sarifSuppression{{Kind: "external"}}
		}
		results = append(results, res)
	}

	log := sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "klarion",
				Version:        r.Version,
				InformationURI: "https://github.com/0x1Adi/Klarion",
				Rules:          rules,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// sarifFinding pairs a finding with its suppression state during emission.
type sarifFinding struct {
	f          finding.Finding
	suppressed bool
}

// sarifLevel maps Klarion severities onto SARIF's fixed level vocabulary.
func sarifLevel(sev finding.Severity) string {
	switch sev {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func sarifMessage(f finding.Finding, redact bool) string {
	return descOrID(f) + " (" + verdictLabel(f.Verdict) + "): " + secretForDisplay(f, redact)
}

func descOrID(f finding.Finding) string {
	if f.Description != "" {
		return f.Description
	}
	return f.RuleID
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

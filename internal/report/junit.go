package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// junitReporter emits JUnit XML so generic CI runners surface secrets as test
// failures. Each active finding is a failing testcase; suppressed findings (when
// shown) become skipped testcases. A clean scan yields one passing testcase so
// the suite is never empty.
type junitReporter struct {
	redact         bool
	showSuppressed bool
}

type junitTestSuite struct {
	XMLName   xml.Name        `xml:"testsuite"`
	Name      string          `xml:"name,attr"`
	Tests     int             `xml:"tests,attr"`
	Failures  int             `xml:"failures,attr"`
	Skipped   int             `xml:"skipped,attr"`
	Time      string          `xml:"time,attr"`
	TestCases []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr,omitempty"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func (j *junitReporter) Write(w io.Writer, r Result) error {
	suite := junitTestSuite{
		Name: "klarion",
		Time: fmt.Sprintf("%.3f", r.Duration.Seconds()),
	}

	for _, f := range r.Findings {
		suite.TestCases = append(suite.TestCases, junitTestCase{
			Name:      caseName(f),
			ClassName: f.RuleID,
			Failure: &junitFailure{
				Message: junitDetail(f, j.redact),
				Type:    string(f.Severity),
				Text:    junitBody(f, j.redact),
			},
		})
		suite.Failures++
	}

	if j.showSuppressed {
		for _, f := range r.Suppressed {
			suite.TestCases = append(suite.TestCases, junitTestCase{
				Name:      caseName(f),
				ClassName: f.RuleID,
				Skipped:   &junitSkipped{Message: "suppressed: " + verdictLabel(f.Verdict)},
			})
			suite.Skipped++
		}
	}

	// Never emit an empty suite: a green run still needs one passing testcase.
	if len(suite.TestCases) == 0 {
		suite.TestCases = append(suite.TestCases, junitTestCase{
			Name:      "no-secrets-detected",
			ClassName: "klarion",
		})
	}
	suite.Tests = len(suite.TestCases)

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(suite); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// caseName is rule:file:line so failures are unique and human-scannable in CI.
func caseName(f finding.Finding) string {
	return fmt.Sprintf("%s:%s:%d", f.RuleID, f.FilePath, f.Line)
}

func junitDetail(f finding.Finding, redact bool) string {
	return fmt.Sprintf("%s secret at %s:%d (%s)",
		f.Severity, f.FilePath, f.Line, secretForDisplay(f, redact))
}

func junitBody(f finding.Finding, redact bool) string {
	body := descOrID(f) + "\n" + junitDetail(f, redact)
	if snippet := firstLine(f.LineText); snippet != "" {
		body += "\n" + contextForDisplay(snippet, f, redact)
	}
	return body
}

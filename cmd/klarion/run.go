package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/0x1Adi/Klarion/internal/baseline"
	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/finding"
	"github.com/0x1Adi/Klarion/internal/report"
	"github.com/0x1Adi/Klarion/internal/verify"
)

// pipeline bundles the constructed components of a scan run so the various
// subcommands (scan, git) share identical detect → verify → filter → report
// behavior.
type pipeline struct {
	cfg      *config.Config
	detector *detect.Detector
	verifier verify.Verifier
}

func newPipeline(cfg *config.Config) (*pipeline, error) {
	det, err := detect.New(cfg)
	if err != nil {
		return nil, err
	}
	v, err := verify.Build(&cfg.AI)
	if err != nil {
		return nil, err
	}
	if flagVerbose {
		fmt.Fprintf(os.Stderr, "klarion: verifier=%s\n", v.Name())
	}
	return &pipeline{cfg: cfg, detector: det, verifier: v}, nil
}

// Close releases pipeline resources — currently flushing the persistent verdict
// cache when one is configured. Losing the cache costs money on the next run,
// not correctness, so a failure here is reported and swallowed rather than
// turning a successful scan into a failed one.
func (p *pipeline) Close() {
	c, ok := p.verifier.(interface {
		Close() error
		Stats() string
	})
	if !ok {
		return
	}
	if err := c.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "klarion: could not write the verdict cache: %v\n", err)
		return
	}
	if flagVerbose {
		fmt.Fprintf(os.Stderr, "klarion: %s\n", c.Stats())
	}
}

// verdictAndFilter runs AI adjudication over the candidates, applies the
// baseline, and splits the set into findings to act on and suppressed ones.
func (p *pipeline) verdictAndFilter(ctx context.Context, candidates []finding.Finding) (active, suppressed []finding.Finding, err error) {
	// Baseline: known-accepted fingerprints are suppressed up front so we
	// don't spend model calls re-adjudicating them.
	if p.cfg.Baseline.Path != "" {
		if bl, lerr := baseline.Load(p.cfg.Baseline.Path); lerr == nil && bl != nil {
			fresh, known := bl.Filter(candidates)
			for i := range known {
				known[i].Suppressed = true
			}
			suppressed = append(suppressed, known...)
			candidates = fresh
		} else if lerr != nil && flagVerbose {
			fmt.Fprintf(os.Stderr, "klarion: baseline: %v\n", lerr)
		}
	}

	if err := verify.Apply(ctx, p.verifier, &p.cfg.AI, candidates); err != nil {
		return nil, nil, err
	}
	kept, fp := verify.FilterFalsePositives(candidates, &p.cfg.AI)
	suppressed = append(suppressed, fp...)
	return kept, suppressed, nil
}

// writeReport renders the result and returns errFindings when any active
// finding is at or above failOn severity.
func (p *pipeline) writeReport(active, suppressed []finding.Finding, filesScanned int, dur time.Duration, failOn finding.Severity) error {
	rep, err := report.New(p.cfg.Report.Format, p.cfg.Report.Redact, p.cfg.Report.ShowSuppressed)
	if err != nil {
		return err
	}
	res := report.Result{
		Findings:     active,
		Suppressed:   suppressed,
		FilesScanned: filesScanned,
		Duration:     dur,
		Tool:         "klarion",
		Version:      version,
	}
	if err := rep.Write(os.Stdout, res); err != nil {
		return err
	}
	if failing(active, failOn) {
		return errFindings
	}
	return nil
}

// failing reports whether any finding meets or exceeds min severity.
func failing(fs []finding.Finding, min finding.Severity) bool {
	for i := range fs {
		if fs[i].Severity.Rank() >= min.Rank() {
			return true
		}
	}
	return false
}

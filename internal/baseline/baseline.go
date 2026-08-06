// Package baseline records the set of findings a repository has already
// accepted, keyed by fingerprint, so that established (known) secrets can be
// separated from newly introduced ones. This is what lets a team adopt Klarion
// on a legacy codebase without drowning in pre-existing hits: `klarion baseline
// create` snapshots today's findings, and subsequent scans only fail on
// fingerprints not in the snapshot.
//
// The on-disk format is a small, human-diffable JSON file. Only redacted
// material is ever stored — a baseline is safe to commit to source control.
package baseline

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/0x1Adi/Klarion/internal/finding"
)

// Entry is the recorded metadata for one accepted fingerprint. It carries just
// enough to make the baseline reviewable in a diff; it never stores the raw
// secret (only its redacted form).
type Entry struct {
	RuleID     string `json:"rule_id"`
	File       string `json:"file"`
	Redacted   string `json:"secret_redacted"`
	AcceptedAt string `json:"accepted_at"` // RFC3339 timestamp
}

// Baseline maps finding fingerprints to their accepted-entry metadata.
type Baseline struct {
	Fingerprints map[string]Entry `json:"fingerprints"`
}

// Load reads a baseline from path. A missing file yields an empty baseline
// (not an error) so the common "no baseline yet" case needs no special-casing
// at the call site. An empty/whitespace file is likewise treated as empty.
func Load(path string) (*Baseline, error) {
	b := &Baseline{Fingerprints: map[string]Entry{}}
	data, err := os.ReadFile(path) // #nosec G304 -- baseline path comes from the operator's config/flags
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return b, nil
		}
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return b, nil
	}
	if err := json.Unmarshal(data, b); err != nil {
		return nil, fmt.Errorf("baseline %s: %w", path, err)
	}
	// Unmarshal leaves the map nil if the key was absent; normalize so callers
	// can index/range without a nil check.
	if b.Fingerprints == nil {
		b.Fingerprints = map[string]Entry{}
	}
	return b, nil
}

// Save writes the baseline to path as indented JSON with a trailing newline
// (friendlier diffs, POSIX-clean file).
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

// Filter partitions findings by baseline membership: new holds findings whose
// fingerprint is absent from the baseline, known holds the rest. Order within
// each slice follows the input.
func (b *Baseline) Filter(findings []finding.Finding) (new, known []finding.Finding) {
	for _, f := range findings {
		if _, ok := b.Fingerprints[f.Fingerprint]; ok {
			known = append(known, f)
		} else {
			new = append(new, f)
		}
	}
	return new, known
}

// FromFindings builds a baseline capturing every given finding. Used by
// `klarion baseline create`. All entries share a single "now" timestamp so a
// freshly created baseline reads as one coherent snapshot.
func FromFindings(findings []finding.Finding) *Baseline {
	b := &Baseline{Fingerprints: make(map[string]Entry, len(findings))}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		b.Fingerprints[f.Fingerprint] = Entry{
			RuleID:     f.RuleID,
			File:       f.FilePath,
			Redacted:   f.Redacted,
			AcceptedAt: now,
		}
	}
	return b
}

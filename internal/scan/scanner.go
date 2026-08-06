// Package scan walks a filesystem tree with a bounded worker pool and runs the
// fast detection pass (internal/detect) over every eligible regular file. It is
// the workhorse behind `klarion scan`: the walker and the detector are both
// concurrency-safe, so scanning parallelizes cleanly across CPU cores.
//
// Gating happens in two places. Path-level filters (ignore globs, allowlisted
// paths) are cheap and applied before a file is read; content-level filters
// (size cap, binary sniff) require a stat/read and live in scanFile. Findings
// whose path is allowlisted are dropped here so downstream stages
// (baseline/allowlist adjudication) only ever see reportable candidates.
package scan

import (
	"context"
	"os"
	"runtime"
	"sync"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/detect"
	"github.com/0x1Adi/Klarion/internal/finding"
)

// Scanner ties a configuration to a detector. It holds no mutable state and is
// safe for concurrent use; ScanPaths may be called repeatedly.
type Scanner struct {
	cfg *config.Config
	det *detect.Detector
}

// New constructs a Scanner. The detector must already be built from the same
// config (see detect.New) so rule/allowlist decisions stay consistent.
func New(cfg *config.Config, det *detect.Detector) *Scanner {
	return &Scanner{cfg: cfg, det: det}
}

// job is one unit of work handed from the walker to a worker.
type job struct {
	abs string // absolute (or as-given) path used to read the file
	rel string // slash path relative to the walk root, used for reporting
}

// ScanPaths walks roots (each a file or directory) with a bounded worker pool
// and returns every finding, the number of files actually content-scanned, and
// the first fatal error encountered.
//
// A "fatal" error is one that aborts the walk (an unreadable root, or context
// cancellation). Per-file problems — unreadable files, oversize files, binary
// blobs, ignored/allowlisted paths — are non-fatal: the file is skipped and the
// scan continues. This fail-open-per-file posture keeps a single bad file from
// hiding secrets in the rest of the tree.
func (s *Scanner) ScanPaths(ctx context.Context, roots []string) ([]finding.Finding, int, error) {
	workers := s.cfg.Scan.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan job)

	var (
		mu       sync.Mutex
		findings []finding.Finding
		scanned  int
	)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			// Drain remaining jobs cheaply once cancelled: returning here would
			// risk the producer blocking on the unbuffered channel.
			if ctx.Err() != nil {
				continue
			}
			fs, ok, err := s.scanFile(ctx, j.abs, j.rel)
			if err != nil || !ok {
				continue
			}
			mu.Lock()
			scanned++
			findings = append(findings, fs...)
			mu.Unlock()
		}
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker()
	}

	// The walk runs on this goroutine and feeds the workers. Closing jobs
	// unblocks the range loops so wg.Wait can return.
	walkErr := s.walk(ctx, roots, jobs)
	close(jobs)
	wg.Wait()

	if walkErr != nil {
		return findings, scanned, walkErr
	}
	if err := ctx.Err(); err != nil {
		return findings, scanned, err
	}
	return findings, scanned, nil
}

// ScanFile scans a single file. It is the exported, standalone entry point used
// by callers that already know the path (e.g. the pre-commit hook) and is also
// reused internally by ScanPaths. relPath is what appears in findings; absPath
// is what is actually read.
func (s *Scanner) ScanFile(ctx context.Context, absPath, relPath string) ([]finding.Finding, error) {
	fs, _, err := s.scanFile(ctx, absPath, relPath)
	return fs, err
}

// scanFile is the shared implementation. The extra bool reports whether the
// file was actually content-scanned (true) versus skipped for a non-error
// reason (allowlisted path, non-regular file, oversize, binary); ScanPaths uses
// it to keep an accurate scanned-file count that the public signature can't
// carry.
func (s *Scanner) scanFile(ctx context.Context, absPath, relPath string) ([]finding.Finding, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	// Allowlisted paths would have every finding dropped, so don't even read
	// them. The caller's baseline/allowlist stages handle the rest.
	if s.cfg.PathAllowlisted(relPath) {
		return nil, false, nil
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}
	if info.Size() > s.cfg.Scan.MaxFileSizeBytes {
		return nil, false, nil
	}
	data, err := os.ReadFile(absPath) // #nosec G304 -- reading the paths under the scan root is the whole job
	if err != nil {
		return nil, false, err
	}
	// Sniff before scanning so binary blobs are not counted as scanned; the
	// detector guards against binary content too, but it would count as work.
	if detect.IsBinary(data) {
		return nil, false, nil
	}
	return s.det.ScanContent(relPath, data), true, nil
}

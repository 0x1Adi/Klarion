package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/0x1Adi/Klarion/internal/config"
	"github.com/0x1Adi/Klarion/internal/detect"
)

// awsKey is a syntactically valid AWS access key ID (AKIA + 16 upper/digit
// chars) that survives the detector's placeholder guard. NOTE: we deliberately
// avoid the canonical "AKIAIOSFODNN7EXAMPLE" here — it lowercases to a string
// containing "example", a builtin stopword, so the detector treats it as a
// placeholder and drops it. This one has no stopword substring and enough
// distinct characters to clear the low-entropy filter.
const awsKey = "AKIA5J7QW3ZN8XR2KVPD"

func newScanner(t *testing.T, tune func(*config.Config)) *Scanner {
	t.Helper()
	cfg := config.Default()
	if tune != nil {
		tune(cfg)
	}
	det, err := detect.New(cfg)
	if err != nil {
		t.Fatalf("detect.New: %v", err)
	}
	return New(cfg, det)
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestScanPathsMixedTree builds a tree exercising every skip reason and asserts
// that exactly the one eligible file is scanned and flagged.
func TestScanPathsMixedTree(t *testing.T) {
	dir := t.TempDir()

	// Eligible: a small text file with a real-shaped AWS key.
	writeFile(t, filepath.Join(dir, "good.txt"),
		[]byte("aws_key = "+awsKey+"\n"))
	// Binary: contains the key but a NUL byte in the first 8 KiB marks it
	// binary, so detect.IsBinary skips it.
	writeFile(t, filepath.Join(dir, "blob.dat"),
		[]byte("aws_key = "+awsKey+"\x00trailing"))
	// Ignored by the default "*.min.js" glob.
	writeFile(t, filepath.Join(dir, "vendor.min.js"),
		[]byte("aws_key = "+awsKey+"\n"))
	// Oversized relative to the tuned cap below.
	big := make([]byte, 0, 256)
	big = append(big, []byte("aws_key = "+awsKey+"\n")...)
	for len(big) <= 64 {
		big = append(big, 'x')
	}
	writeFile(t, filepath.Join(dir, "big.txt"), big)

	s := newScanner(t, func(c *config.Config) {
		c.Scan.MaxFileSizeBytes = 64 // good.txt (~30B) passes; big.txt does not
	})

	findings, scanned, err := s.ScanPaths(context.Background(), []string{dir})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if scanned != 1 {
		t.Fatalf("scanned = %d, want 1 (only good.txt)", scanned)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "aws-access-key-id" {
		t.Errorf("RuleID = %q, want aws-access-key-id", f.RuleID)
	}
	if f.FilePath != "good.txt" {
		t.Errorf("FilePath = %q, want good.txt (relative to root)", f.FilePath)
	}
	if f.Secret != awsKey {
		t.Errorf("Secret = %q, want %q", f.Secret, awsKey)
	}
}

// TestScanPathsSingleFileRoot checks that a file (not dir) passed as a root is
// scanned and reported by its base name.
func TestScanPathsSingleFileRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.env")
	writeFile(t, path, []byte("aws_key = "+awsKey+"\n"))

	s := newScanner(t, nil)
	findings, scanned, err := s.ScanPaths(context.Background(), []string{path})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if scanned != 1 || len(findings) != 1 {
		t.Fatalf("scanned=%d findings=%d, want 1/1", scanned, len(findings))
	}
	if findings[0].FilePath != "creds.env" {
		t.Errorf("FilePath = %q, want creds.env", findings[0].FilePath)
	}
}

// TestScanPathsMissingRoot: a non-existent root is a fatal error.
func TestScanPathsMissingRoot(t *testing.T) {
	s := newScanner(t, nil)
	_, _, err := s.ScanPaths(context.Background(),
		[]string{filepath.Join(t.TempDir(), "does-not-exist")})
	if err == nil {
		t.Fatal("expected error for missing root, got nil")
	}
}

// TestScanPathsConcurrent scans many small files to shake out data races in the
// worker-pool aggregation (run with -race). Every file yields exactly one
// finding, so the totals are deterministic regardless of scheduling.
func TestScanPathsConcurrent(t *testing.T) {
	dir := t.TempDir()
	const n = 200
	for i := 0; i < n; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%03d.txt", i)),
			[]byte("aws_key = "+awsKey+"\n"))
	}

	s := newScanner(t, func(c *config.Config) { c.Scan.Workers = 8 })

	findings, scanned, err := s.ScanPaths(context.Background(), []string{dir})
	if err != nil {
		t.Fatalf("ScanPaths: %v", err)
	}
	if scanned != n {
		t.Fatalf("scanned = %d, want %d", scanned, n)
	}
	if len(findings) != n {
		t.Fatalf("findings = %d, want %d", len(findings), n)
	}

	// Each file must be represented exactly once.
	seen := make(map[string]bool, n)
	for _, f := range findings {
		if seen[f.FilePath] {
			t.Fatalf("duplicate finding for %s", f.FilePath)
		}
		seen[f.FilePath] = true
	}
	if len(seen) != n {
		files := make([]string, 0, len(seen))
		for k := range seen {
			files = append(files, k)
		}
		sort.Strings(files)
		t.Fatalf("distinct files = %d, want %d", len(seen), n)
	}
}

// TestScanPathsCancellation: a cancelled context surfaces as the returned error
// (findings gathered before cancellation are still returned).
func TestScanPathsCancellation(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		writeFile(t, filepath.Join(dir, fmt.Sprintf("f%02d.txt", i)),
			[]byte("aws_key = "+awsKey+"\n"))
	}
	s := newScanner(t, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before starting

	_, _, err := s.ScanPaths(ctx, []string{dir})
	if err == nil {
		t.Fatal("expected context error, got nil")
	}
}

// TestScanFileBinaryAndOversize exercises the standalone ScanFile skip paths.
func TestScanFileBinaryAndOversize(t *testing.T) {
	dir := t.TempDir()
	s := newScanner(t, func(c *config.Config) { c.Scan.MaxFileSizeBytes = 64 })

	bin := filepath.Join(dir, "b.dat")
	writeFile(t, bin, []byte(awsKey+"\x00"))
	if fs, err := s.ScanFile(context.Background(), bin, "b.dat"); err != nil || fs != nil {
		t.Errorf("binary: got %d findings err=%v, want 0/nil", len(fs), err)
	}

	big := append([]byte(awsKey+"\n"), make([]byte, 128)...)
	over := filepath.Join(dir, "big.txt")
	writeFile(t, over, big)
	if fs, err := s.ScanFile(context.Background(), over, "big.txt"); err != nil || fs != nil {
		t.Errorf("oversize: got %d findings err=%v, want 0/nil", len(fs), err)
	}
}

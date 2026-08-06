package scan

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// walk enumerates every eligible regular file under roots and sends a job for
// it. Errors from a single root abort the whole walk (an unreadable root is a
// caller mistake worth surfacing); per-entry problems inside a tree are
// swallowed so the scan is robust to unreadable subdirectories.
func (s *Scanner) walk(ctx context.Context, roots []string, jobs chan<- job) error {
	for _, root := range roots {
		if err := s.walkRoot(ctx, root, jobs); err != nil {
			return err
		}
	}
	return nil
}

// walkRoot handles a single root, which may be a file or a directory. Reported
// paths are computed relative to root so findings are stable regardless of the
// absolute location the scan was launched from.
func (s *Scanner) walkRoot(ctx context.Context, root string, jobs chan<- job) error {
	// Stat (not Lstat): a root given as a symlink is always resolved, even when
	// FollowSymlinks is off — the user pointed us at it explicitly.
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		// Single-file root: report it by its base name.
		rel := filepath.ToSlash(filepath.Base(root))
		if s.cfg.PathIgnored(rel) {
			return nil
		}
		return s.emit(ctx, jobs, root, rel)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entry: skip it (and its subtree, if a dir) but keep
			// walking the rest of the tree.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return s.walkSymlink(ctx, jobs, path, rel)

		case d.IsDir():
			// Prune whole ignored subtrees when the directory path itself
			// matches an ignore glob (e.g. a "build/" rule). Files inside
			// non-matching dirs are still filtered individually below.
			if rel != "." && s.cfg.PathIgnored(rel) {
				return fs.SkipDir
			}
			return nil

		case d.Type().IsRegular():
			if s.cfg.PathIgnored(rel) {
				return nil
			}
			return s.emit(ctx, jobs, path, rel)

		default:
			// Devices, sockets, named pipes: never scanned.
			return nil
		}
	})
}

// walkSymlink decides what to do with a symlink encountered mid-walk. With
// following disabled it is ignored. When enabled we follow it only to regular
// files: descending into symlinked directories is skipped to avoid cycles and
// double-scanning, which a filesystem scanner cannot cheaply rule out.
func (s *Scanner) walkSymlink(ctx context.Context, jobs chan<- job, path, rel string) error {
	if !s.cfg.Scan.FollowSymlinks {
		return nil
	}
	target, err := os.Stat(path) // resolves the link
	if err != nil {
		return nil // dangling link: skip, non-fatal
	}
	if target.IsDir() {
		return nil // do not descend symlinked dirs (cycle safety)
	}
	if s.cfg.PathIgnored(rel) {
		return nil
	}
	return s.emit(ctx, jobs, path, rel)
}

// emit pushes a job, unblocking on context cancellation so the walk goroutine
// never wedges when workers have stopped consuming.
func (s *Scanner) emit(ctx context.Context, jobs chan<- job, abs, rel string) error {
	select {
	case jobs <- job{abs: abs, rel: rel}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

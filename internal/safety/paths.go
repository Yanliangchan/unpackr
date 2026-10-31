// Package safety holds the input-validation, path-guard and sandbox
// primitives. Nothing in it executes analysed content.
package safety

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrEscapes is returned when a path would leave its root.
var ErrEscapes = errors.New("path escapes the output root")

// SecureJoin joins an untrusted relative name (for example an archive member)
// to root and guarantees the result is lexically inside root. Absolute paths,
// ".." traversal, NUL bytes and Windows drive/volume prefixes are rejected.
// It does not touch the filesystem; extraction code must additionally refuse
// to follow symlinks.
func SecureJoin(root, name string) (string, error) {
	if name == "" || strings.ContainsRune(name, 0) {
		return "", fmt.Errorf("invalid member name %q", name)
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if strings.HasPrefix(name, "/") || (len(name) >= 2 && name[1] == ':') {
		return "", fmt.Errorf("%w: absolute path %q", ErrEscapes, name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrEscapes, name)
	}
	full := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %q", ErrEscapes, name)
	}
	return full, nil
}

// SameFile reports whether two paths refer to the same existing file. If the
// second does not exist it is not the same file.
func SameFile(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}

// OpenInput opens an analysis input read-only and verifies it is a regular
// file no larger than max (0 means unlimited).
func OpenInput(path string, max int64) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is not a regular file", path)
	}
	if max > 0 && st.Size() > max {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s is %d bytes, above the configured limit of %d", path, st.Size(), max)
	}
	return f, st, nil
}

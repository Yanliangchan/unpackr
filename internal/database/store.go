package database

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// SchemaVersion is the layout of the index file. A file with a higher number
// was written by a newer UNPACKR and is refused, never rewritten.
const SchemaVersion = 1

// maxIndexBytes bounds the index file read on open.
const maxIndexBytes = 512 << 20

// lockWait is how long a second UNPACKR waits for the store.
const lockWait = 5 * time.Second

// ErrNotFound means nothing is stored under that key.
var ErrNotFound = errors.New("not found")

// Sample is what is remembered about one file (never its bytes).
type Sample struct {
	SHA256, MD5, SHA1             string
	Size                          int64
	LastName, FirstSeen, LastSeen string
	TimesSeen                     int
}

// Analysis is the summary of one stored analysis; the full report is a
// separate compressed file.
type Analysis struct {
	ID                                              int64
	SHA256, At, ToolVersion, Profile, Format, Arch  string
	PackingState, PackingFamily, Language, Compiler string
	Findings, High, Medium                          int
	Bytes                                           int64
}

// Edge links an unpacked or extracted file to the file it came from.
type Edge struct{ Parent, Child, Kind, Tool string }

// CaseLink puts a sample in a case.
type CaseLink struct{ SHA256, AddedAt string }

// CaseRec is a case header and its samples.
type CaseRec struct {
	ID                                   int64
	Name, Description, Status, CreatedAt string
	Samples                              []CaseLink
}

// Note is an analyst note; SHA256 is empty for a note about the whole case.
type Note struct {
	ID, CaseID       int64
	SHA256, At, Body string
}

// Event is one line of a case timeline.
type Event struct {
	ID, CaseID               int64
	At, Kind, SHA256, Detail string
}

// Index is everything except the report bodies.
type Index struct {
	Version                                     int
	NextAnalysis, NextCase, NextNote, NextEvent int64
	Samples                                     map[string]*Sample
	Analyses                                    map[string][]*Analysis
	Features                                    map[string][][2]string
	Edges                                       []Edge
	Cases                                       []*CaseRec
	Notes                                       []Note
	Timeline                                    []Event
}

func newIndex() *Index {
	return &Index{Version: SchemaVersion, NextAnalysis: 1, NextCase: 1, NextNote: 1, NextEvent: 1,
		Samples: map[string]*Sample{}, Analyses: map[string][]*Analysis{}, Features: map[string][][2]string{}}
}

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// reportsDir holds the compressed reports next to the index file.
func (d *DB) reportsDir() string { return d.path + ".reports" }

func (d *DB) reportPath(sha string, id int64) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("refusing to store a report under %q: not a SHA-256", sha)
	}
	return filepath.Join(d.reportsDir(), sha, fmt.Sprintf("%d.json.gz", id)), nil
}

func (d *DB) writeReport(sha string, id int64, blob []byte) error {
	p, err := d.reportPath(sha, id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return writeAtomic(p, blob)
}

func (d *DB) removeReport(sha string, id int64) {
	if p, err := d.reportPath(sha, id); err == nil {
		_ = os.Remove(p)
		_ = os.Remove(filepath.Dir(p)) // only succeeds when empty
	}
}

// writeAtomic replaces path with data via a synced temporary file, so a crash
// leaves either the old or the new content.
func writeAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if err := f.Chmod(0o600); err != nil && !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func (d *DB) load() error {
	f, err := os.Open(d.path) //nolint:gosec // the configured database path
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck // read-only
	data, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxIndexBytes {
		return errors.New("the database index is too large")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		d.ix = newIndex()
		d.dirty = true
		return nil
	}
	var ix Index
	if err := json.Unmarshal(data, &ix); err != nil {
		return fmt.Errorf("the database index is damaged: %w", err)
	}
	if ix.Version > SchemaVersion {
		return fmt.Errorf("%w (schema %d, this build knows %d)", ErrNewerSchema, ix.Version, SchemaVersion)
	}
	if ix.Samples == nil {
		ix.Samples = map[string]*Sample{}
	}
	if ix.Analyses == nil {
		ix.Analyses = map[string][]*Analysis{}
	}
	if ix.Features == nil {
		ix.Features = map[string][][2]string{}
	}
	d.ix = &ix
	return nil
}

// Flush writes pending changes. Close calls it; commands that must not lose a
// change on a later failure call it themselves.
func (d *DB) Flush() error {
	if !d.dirty {
		return nil
	}
	data, err := json.Marshal(d.ix)
	if err != nil {
		return err
	}
	if err := writeAtomic(d.path, data); err != nil {
		return err
	}
	d.dirty = false
	return nil
}

// Index exposes the data to the cases package. Call Touch after changing it.
func (d *DB) Index() *Index { return d.ix }

// Touch marks the index as changed.
func (d *DB) Touch() { d.dirty = true }

func gz(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close() //nolint:errcheck // in-memory reader
	out, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxReportBytes {
		return nil, errors.New("stored report is too large")
	}
	return out, nil
}

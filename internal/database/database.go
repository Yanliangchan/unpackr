// Package database is UNPACKR's local memory: which files it has analysed,
// what it found, and the cases they belong to. It stores hashes, reports and
// notes, never the samples. The store is a small JSON index plus one
// compressed report file per analysis, kept in a directory only the owner can
// read. Writes are atomic and a lock file keeps two UNPACKR processes from
// overwriting each other.
package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/comparison"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MaxStoredAnalyses is how many analyses are kept per sample.
const MaxStoredAnalyses = 20

// maxReportBytes bounds a decompressed stored report when it is read back.
const maxReportBytes = 256 << 20

// ErrNewerSchema means the database was written by a newer UNPACKR.
var ErrNewerSchema = errors.New("the database was created by a newer version of UNPACKR")

// ErrBusy means another UNPACKR process is using the database.
var ErrBusy = errors.New("the database is in use by another UNPACKR process; try again in a moment")

// DB is an open database. It is held open (and locked) until Close.
type DB struct {
	path  string
	ix    *Index
	lock  *fileLock
	dirty bool
}

// DefaultPath is where the database lives unless configured otherwise.
func DefaultPath() string {
	if d := config.DataDir(); d != "" {
		return filepath.Join(d, "db.json")
	}
	return ""
}

// Open creates (mode 0700 directory, 0600 files) and loads the database.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("no database path: set database_path or use_database: false")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	lk, err := lockFile(path+".lock", lockWait)
	if err != nil {
		return nil, err
	}
	d := &DB{path: path, lock: lk}
	if _, serr := os.Stat(path); os.IsNotExist(serr) {
		d.ix, d.dirty = newIndex(), true
		if err := d.Flush(); err != nil {
			lk.unlock()
			return nil, err
		}
		return d, nil
	}
	if err := d.load(); err != nil {
		lk.unlock()
		return nil, err
	}
	if err := d.Flush(); err != nil { // an empty file becomes a valid index
		lk.unlock()
		return nil, err
	}
	return d, nil
}

// Path returns the database file.
func (d *DB) Path() string { return d.path }

// Close writes pending changes and releases the lock.
func (d *DB) Close() error {
	if d.lock == nil {
		return nil
	}
	err := d.Flush()
	d.lock.unlock()
	d.lock = nil
	return err
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Lookup returns what is remembered about sha256, or nil if the file is new.
// The comparison with the previous analysis needs the current report, so it
// is filled in by Annotate.
func (d *DB) Lookup(sha string) (*models.KnownSample, error) {
	s := d.ix.Samples[sha]
	if s == nil {
		return nil, nil
	}
	k := models.KnownSample{FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, TimesSeen: s.TimesSeen}
	as := d.ix.Analyses[sha]
	k.Analyses = len(as)
	if n := len(as); n > 0 {
		a := as[n-1]
		k.Last = &models.PreviousAnalysis{At: a.At, ToolVersion: a.ToolVersion, Profile: a.Profile, PackingState: a.PackingState,
			PackingFamily: a.PackingFamily, Language: a.Language, Compiler: a.Compiler, Findings: a.Findings, High: a.High, Medium: a.Medium}
	}
	k.Cases = []string{}
	for _, c := range d.ix.Cases {
		for _, l := range c.Samples {
			if l.SHA256 == sha {
				k.Cases = append(k.Cases, c.Name)
				break
			}
		}
	}
	sort.Strings(k.Cases)
	k.Derived = []string{}
	for _, e := range d.ix.Edges {
		if e.Parent == sha {
			k.Derived = append(k.Derived, e.Child)
		}
	}
	sort.Strings(k.Derived)
	return &k, nil
}

// LoadReport returns the most recent stored report for sha256.
func (d *DB) LoadReport(sha string) (*models.Report, error) {
	as := d.ix.Analyses[sha]
	if len(as) == 0 {
		return nil, ErrNotFound
	}
	p, err := d.reportPath(sha, as[len(as)-1].ID)
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(p) //nolint:gosec // path built from a validated SHA-256 and a numeric id
	if err != nil {
		return nil, err
	}
	raw, err := gunzip(blob)
	if err != nil {
		return nil, err
	}
	var r models.Report
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Annotate attaches what is remembered about rep's file, including what
// changed since the last analysis. It must be called before Record.
func (d *DB) Annotate(rep *models.Report) error {
	k, err := d.Lookup(rep.File.Hashes.SHA256)
	if err != nil || k == nil {
		return err
	}
	if prev, lerr := d.LoadReport(rep.File.Hashes.SHA256); lerr == nil {
		c := comparison.Diff(prev, rep)
		c.Notes = nil
		k.Changes = c
		if prev.Tool.Version != rep.Tool.Version {
			k.ToolChange = prev.Tool.Version + " -> " + rep.Tool.Version
		}
	}
	rep.Known = k
	return nil
}

func hypName(hs []models.Hypothesis) string {
	if len(hs) == 0 {
		return ""
	}
	return hs[0].Name
}

// Record stores the analysis (and, recursively, any unpacked layers) and
// refreshes the sample's bookkeeping. Samples are never stored.
func (d *DB) Record(rep *models.Report) error {
	if err := d.record(rep, nil); err != nil {
		return err
	}
	d.dirty = true
	return nil
}

func (d *DB) record(rep *models.Report, parent *models.Artifact) error {
	h, at := rep.File.Hashes, now()
	if !shaRe.MatchString(h.SHA256) {
		return fmt.Errorf("refusing to record a file without a valid SHA-256 (%q)", h.SHA256)
	}
	stored := *rep
	stored.Known = nil // the memory is recomputed on read
	raw, err := json.Marshal(&stored)
	if err != nil {
		return err
	}
	blob, err := gz(raw)
	if err != nil {
		return err
	}
	var fmtName, arch, pstate, pfam, lang, comp string
	if rep.Identification != nil {
		fmtName = rep.Identification.Primary
	}
	if rep.Binary != nil {
		arch = rep.Binary.Arch
	}
	if a := rep.Analysis; a != nil {
		pstate, pfam = a.Packing.State, a.Packing.Family
		lang, comp = hypName(a.Fingerprint.Languages), hypName(a.Fingerprint.Compilers)
	}
	high, med := 0, 0
	for _, f := range rep.Findings {
		switch f.Severity {
		case models.SeverityHigh:
			high++
		case models.SeverityMedium:
			med++
		}
	}

	id := d.ix.NextAnalysis
	// The report file goes first: a crash before the index is saved leaves an
	// unreferenced file, never an index entry without its report.
	if err := d.writeReport(h.SHA256, id, blob); err != nil {
		return err
	}
	d.ix.NextAnalysis++

	if s := d.ix.Samples[h.SHA256]; s != nil {
		s.LastName, s.LastSeen = rep.File.Name, at
		s.TimesSeen++
	} else {
		d.ix.Samples[h.SHA256] = &Sample{SHA256: h.SHA256, MD5: h.MD5, SHA1: h.SHA1, Size: rep.File.Size, LastName: rep.File.Name, FirstSeen: at, LastSeen: at, TimesSeen: 1}
	}
	as := append(d.ix.Analyses[h.SHA256], &Analysis{ID: id, SHA256: h.SHA256, At: at, ToolVersion: rep.Tool.Version, Profile: rep.Profile,
		Format: fmtName, Arch: arch, PackingState: pstate, PackingFamily: pfam, Language: lang, Compiler: comp,
		Findings: len(rep.Findings), High: high, Medium: med, Bytes: int64(len(blob))})
	for len(as) > MaxStoredAnalyses {
		d.removeReport(h.SHA256, as[0].ID)
		as = as[1:]
	}
	d.ix.Analyses[h.SHA256] = as

	// Features are replaced wholesale so removed indicators do not linger.
	seen := map[[2]string]bool{}
	var feats [][2]string
	for _, f := range Features(rep) {
		if !seen[f] {
			seen[f] = true
			feats = append(feats, f)
		}
	}
	d.ix.Features[h.SHA256] = feats

	if parent != nil && shaRe.MatchString(parent.ParentSHA256) {
		e := Edge{Parent: parent.ParentSHA256, Child: h.SHA256, Kind: parent.Kind, Tool: parent.Tool + " " + parent.ToolVersion}
		replaced := false
		for i, old := range d.ix.Edges {
			if old.Parent == e.Parent && old.Child == e.Child && old.Kind == e.Kind {
				d.ix.Edges[i], replaced = e, true
				break
			}
		}
		if !replaced {
			d.ix.Edges = append(d.ix.Edges, e)
		}
	}
	// Cases that contain this sample learn that it was analysed again.
	detail := fmt.Sprintf("analysed with UNPACKR %s (%s): packing %s", rep.Tool.Version, rep.Profile, orDash(pstate))
	for _, c := range d.ix.Cases {
		for _, l := range c.Samples {
			if l.SHA256 == h.SHA256 {
				d.AddEvent(c.ID, at, "analysed", h.SHA256, detail)
				break
			}
		}
	}
	for i := range rep.Artifacts {
		a := &rep.Artifacts[i]
		if a.Report == nil {
			continue
		}
		if err := d.record(a.Report, a); err != nil {
			return err
		}
	}
	return nil
}

// AddEvent appends a case timeline entry. The caller flushes or closes.
func (d *DB) AddEvent(caseID int64, at, kind, sha, detail string) {
	d.ix.Timeline = append(d.ix.Timeline, Event{ID: d.ix.NextEvent, CaseID: caseID, At: at, Kind: kind, SHA256: sha, Detail: detail})
	d.ix.NextEvent++
	d.dirty = true
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Features lists the pivot values of a report as (kind, value) pairs.
func Features(rep *models.Report) [][2]string {
	var out [][2]string
	add := func(k, v string) {
		if v != "" && len(v) <= 512 {
			out = append(out, [2]string{k, v})
		}
	}
	if b := rep.Binary; b != nil {
		add("imphash", b.ImportHash)
		var parts []string
		for _, s := range b.Sections {
			parts = append(parts, fmt.Sprintf("%s:%s:%x", s.Name, s.Perms, s.RawSize))
		}
		sort.Strings(parts)
		if len(parts) > 0 {
			add("section-layout", strings.Join(parts, ","))
		}
	}
	if a := rep.Analysis; a != nil {
		for _, i := range a.Indicators {
			add("indicator:"+i.Type, i.Value)
			// Different URLs on one server are the same infrastructure, so
			// hosts are a pivot of their own.
			switch i.Type {
			case "url":
				add("host", hostOf(i.Value))
			case "domain", "ipv4":
				add("host", strings.ToLower(i.Value))
			}
		}
		for _, c := range a.Capabilities {
			add("capability", c.ID)
			for _, t := range c.Attack {
				add("attack", t)
			}
		}
		for _, y := range a.Yara {
			if y.Status == "tested" {
				add("yara", y.Rule)
			}
		}
		if a.Packing.Family != "" {
			add("packer", a.Packing.Family)
		}
		add("language", hypName(a.Fingerprint.Languages))
		add("ssdeep", a.Fuzzy.SSDeep)
		add("tlsh", a.Fuzzy.TLSH)
	}
	return out
}

// hostOf extracts the host name of a URL, or "" if it has none.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Stats summarises the database.
type Stats struct {
	Samples, Analyses, Cases, Indicators int
	Path                                 string
	Bytes                                int64
}

// Stats counts what is stored.
func (d *DB) Stats() (Stats, error) {
	s := Stats{Path: d.path, Samples: len(d.ix.Samples), Cases: len(d.ix.Cases)}
	for _, as := range d.ix.Analyses {
		s.Analyses += len(as)
		for _, a := range as {
			s.Bytes += a.Bytes
		}
	}
	for _, fs := range d.ix.Features {
		for _, f := range fs {
			if strings.HasPrefix(f[0], "indicator:") {
				s.Indicators++
			}
		}
	}
	if st, err := os.Stat(d.path); err == nil {
		s.Bytes += st.Size()
	}
	return s, nil
}

// SampleRef identifies a stored sample in search results.
type SampleRef struct {
	SHA256, Name, FirstSeen, LastSeen, Format, Packing string
	TimesSeen                                          int
}

// maxFindResults bounds a search.
const maxFindResults = 200

// Find returns samples carrying a pivot value. kind "ioc" searches every
// indicator type; "hash" matches a SHA-256 prefix.
func (d *DB) Find(kind, value string) ([]SampleRef, error) {
	var match func(sha string) bool
	hasFeature := func(sha string, ok func(kind, val string) bool) bool {
		for _, f := range d.ix.Features[sha] {
			if ok(f[0], f[1]) {
				return true
			}
		}
		return false
	}
	switch kind {
	case "hash":
		if len(value) < 6 || strings.ContainsAny(value, "%_") {
			return nil, errors.New("give at least 6 hex characters of a SHA-256")
		}
		prefix := strings.ToLower(value)
		match = func(sha string) bool { return strings.HasPrefix(sha, prefix) }
	case "ioc":
		lower := strings.ToLower(value)
		match = func(sha string) bool {
			return hasFeature(sha, func(k, v string) bool {
				return (strings.HasPrefix(k, "indicator:") && v == value) || (k == "host" && v == lower)
			})
		}
	default:
		match = func(sha string) bool {
			return hasFeature(sha, func(k, v string) bool { return k == kind && v == value })
		}
	}
	var out []SampleRef
	for sha, s := range d.ix.Samples {
		if !match(sha) {
			continue
		}
		r := SampleRef{SHA256: sha, Name: s.LastName, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, TimesSeen: s.TimesSeen}
		if as := d.ix.Analyses[sha]; len(as) > 0 {
			r.Format, r.Packing = as[len(as)-1].Format, as[len(as)-1].PackingState
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].SHA256 < out[j].SHA256
	})
	if len(out) > maxFindResults {
		out = out[:maxFindResults]
	}
	return out, nil
}

// Forget removes a sample and everything derived from it (analyses, features,
// case links). Notes attached to a case stay; their sample reference is cleared.
func (d *DB) Forget(sha string) (bool, error) {
	if d.ix.Samples[sha] == nil {
		return false, nil
	}
	for _, a := range d.ix.Analyses[sha] {
		d.removeReport(sha, a.ID)
	}
	delete(d.ix.Samples, sha)
	delete(d.ix.Analyses, sha)
	delete(d.ix.Features, sha)
	edges := d.ix.Edges[:0]
	for _, e := range d.ix.Edges {
		if e.Parent != sha && e.Child != sha {
			edges = append(edges, e)
		}
	}
	d.ix.Edges = edges
	for _, c := range d.ix.Cases {
		links := c.Samples[:0]
		for _, l := range c.Samples {
			if l.SHA256 != sha {
				links = append(links, l)
			}
		}
		c.Samples = links
	}
	for i := range d.ix.Notes {
		if d.ix.Notes[i].SHA256 == sha {
			d.ix.Notes[i].SHA256 = ""
		}
	}
	d.dirty = true
	return true, d.Flush()
}

// Now is the timestamp format used throughout the database.
func Now() string { return now() }

// Package database is UNPACKR's local memory: which files it has analysed,
// what it found, and the cases they belong to. It stores hashes, reports and
// notes, never the samples. The store is SQLite (pure Go, no server) in a
// file only the owner can read.
package database

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"github.com/Yanliangchan/unpackr/internal/comparison"
	"github.com/Yanliangchan/unpackr/internal/config"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

//go:embed migrations/*.sql
var migrations embed.FS

// MaxStoredAnalyses is how many analyses are kept per sample.
const MaxStoredAnalyses = 20

// maxReportBytes bounds a decompressed stored report when it is read back.
const maxReportBytes = 256 << 20

// ErrNewerSchema means the database was written by a newer UNPACKR.
var ErrNewerSchema = errors.New("the database was created by a newer version of UNPACKR")

// DB is an open database.
type DB struct {
	sql  *sql.DB
	path string
}

// DefaultPath is where the database lives unless configured otherwise.
func DefaultPath() string {
	if d := config.DataDir(); d != "" {
		return filepath.Join(d, "db.sqlite")
	}
	return ""
}

// Open creates (mode 0700 directory, 0600 file) and migrates the database.
func Open(path string) (*DB, error) {
	if path == "" {
		return nil, errors.New("no database path: set database_path or use_database: false")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, cerr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if cerr != nil {
			return nil, cerr
		}
		_ = f.Close()
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	s, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s.SetMaxOpenConns(1) // single writer; the CLI records after analysis finishes
	d := &DB{sql: s, path: path}
	if err := d.migrate(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return d, nil
}

// Path returns the database file.
func (d *DB) Path() string { return d.path }

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

func (d *DB) migrate() error {
	var version int
	if err := d.sql.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	ents, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	var files []string
	for _, e := range ents {
		files = append(files, e.Name())
	}
	sort.Strings(files)
	if version > len(files) {
		return fmt.Errorf("%w (schema %d, this build knows %d)", ErrNewerSchema, version, len(files))
	}
	for i := version; i < len(files); i++ {
		b, err := migrations.ReadFile("migrations/" + files[i])
		if err != nil {
			return err
		}
		tx, err := d.sql.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(b)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %s: %w", files[i], err)
		}
		if _, err := tx.Exec("PRAGMA user_version = " + strconv.Itoa(i+1)); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

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

// Lookup returns what is remembered about sha256, or nil if the file is new.
// The comparison with the previous analysis needs the current report, so it
// is filled in by Annotate.
func (d *DB) Lookup(sha string) (*models.KnownSample, error) {
	var k models.KnownSample
	err := d.sql.QueryRow("SELECT first_seen, last_seen, times_seen FROM samples WHERE sha256 = ?", sha).Scan(&k.FirstSeen, &k.LastSeen, &k.TimesSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := d.sql.QueryRow("SELECT count(*) FROM analyses WHERE sha256 = ?", sha).Scan(&k.Analyses); err != nil {
		return nil, err
	}
	var p models.PreviousAnalysis
	err = d.sql.QueryRow(`SELECT analysed_at, tool_version, profile, packing_state, packing_family, language, compiler, findings, high, medium
		FROM analyses WHERE sha256 = ? ORDER BY id DESC LIMIT 1`, sha).
		Scan(&p.At, &p.ToolVersion, &p.Profile, &p.PackingState, &p.PackingFamily, &p.Language, &p.Compiler, &p.Findings, &p.High, &p.Medium)
	if err == nil {
		k.Last = &p
	}
	k.Cases = []string{}
	rows, err := d.sql.Query("SELECT c.name FROM cases c JOIN case_samples cs ON cs.case_id = c.id WHERE cs.sha256 = ? ORDER BY c.name", sha)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		k.Cases = append(k.Cases, n)
	}
	k.Derived = []string{}
	r2, err := d.sql.Query("SELECT child FROM edges WHERE parent = ? ORDER BY child", sha)
	if err != nil {
		return nil, err
	}
	defer r2.Close() //nolint:errcheck // read-only
	for r2.Next() {
		var c string
		if err := r2.Scan(&c); err != nil {
			return nil, err
		}
		k.Derived = append(k.Derived, c)
	}
	return &k, rows.Err()
}

// LoadReport returns the most recent stored report for sha256.
func (d *DB) LoadReport(sha string) (*models.Report, error) {
	var blob []byte
	err := d.sql.QueryRow("SELECT report_gz FROM analyses WHERE sha256 = ? ORDER BY id DESC LIMIT 1", sha).Scan(&blob)
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
	tx, err := d.sql.Begin()
	if err != nil {
		return err
	}
	if err := d.record(tx, rep, nil); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (d *DB) record(tx *sql.Tx, rep *models.Report, parent *models.Artifact) error {
	h, at := rep.File.Hashes, now()
	_, err := tx.Exec(`INSERT INTO samples(sha256, md5, sha1, size, last_name, first_seen, last_seen, times_seen) VALUES (?,?,?,?,?,?,?,1)
		ON CONFLICT(sha256) DO UPDATE SET last_name = excluded.last_name, last_seen = excluded.last_seen, times_seen = times_seen + 1`,
		h.SHA256, h.MD5, h.SHA1, rep.File.Size, rep.File.Name, at, at)
	if err != nil {
		return err
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
	if _, err := tx.Exec(`INSERT INTO analyses(sha256, analysed_at, tool_version, profile, format, architecture, packing_state, packing_family, language, compiler, findings, high, medium, report_gz)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, h.SHA256, at, rep.Tool.Version, rep.Profile, fmtName, arch, pstate, pfam, lang, comp, len(rep.Findings), high, med, blob); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM analyses WHERE sha256 = ? AND id NOT IN (SELECT id FROM analyses WHERE sha256 = ? ORDER BY id DESC LIMIT ?)`, h.SHA256, h.SHA256, MaxStoredAnalyses); err != nil {
		return err
	}
	// Features are replaced wholesale so removed indicators do not linger.
	if _, err := tx.Exec("DELETE FROM features WHERE sha256 = ?", h.SHA256); err != nil {
		return err
	}
	for _, f := range Features(rep) {
		if _, err := tx.Exec("INSERT OR IGNORE INTO features(sha256, kind, value) VALUES (?,?,?)", h.SHA256, f[0], f[1]); err != nil {
			return err
		}
	}
	if parent != nil {
		if _, err := tx.Exec("INSERT OR REPLACE INTO edges(parent, child, kind, tool) VALUES (?,?,?,?)", parent.ParentSHA256, h.SHA256, parent.Kind, parent.Tool+" "+parent.ToolVersion); err != nil {
			return err
		}
	}
	// Cases that contain this sample learn that it was analysed again.
	detail := fmt.Sprintf("analysed with UNPACKR %s (%s): packing %s", rep.Tool.Version, rep.Profile, orDash(pstate))
	if _, err := tx.Exec(`INSERT INTO timeline(case_id, at, kind, sha256, detail) SELECT case_id, ?, 'analysed', ?, ? FROM case_samples WHERE sha256 = ?`, at, h.SHA256, detail, h.SHA256); err != nil {
		return err
	}
	for i := range rep.Artifacts {
		a := &rep.Artifacts[i]
		if a.Report == nil {
			continue
		}
		if err := d.record(tx, a.Report, a); err != nil {
			return err
		}
	}
	return nil
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
	s := Stats{Path: d.path}
	for q, dst := range map[string]*int{
		"SELECT count(*) FROM samples": &s.Samples, "SELECT count(*) FROM analyses": &s.Analyses,
		"SELECT count(*) FROM cases": &s.Cases, "SELECT count(*) FROM features WHERE kind LIKE 'indicator:%'": &s.Indicators,
	} {
		if err := d.sql.QueryRow(q).Scan(dst); err != nil {
			return s, err
		}
	}
	if st, err := os.Stat(d.path); err == nil {
		s.Bytes = st.Size()
	}
	return s, nil
}

// SampleRef identifies a stored sample in search results.
type SampleRef struct {
	SHA256, Name, FirstSeen, LastSeen, Format, Packing string
	TimesSeen                                          int
}

// Find returns samples carrying a pivot value. kind "ioc" searches every
// indicator type; "hash" matches a SHA-256 prefix.
func (d *DB) Find(kind, value string) ([]SampleRef, error) {
	var rows *sql.Rows
	var err error
	base := `SELECT s.sha256, s.last_name, s.first_seen, s.last_seen, s.times_seen,
		COALESCE((SELECT format FROM analyses a WHERE a.sha256 = s.sha256 ORDER BY id DESC LIMIT 1), ''),
		COALESCE((SELECT packing_state FROM analyses a WHERE a.sha256 = s.sha256 ORDER BY id DESC LIMIT 1), '')
		FROM samples s `
	switch kind {
	case "hash":
		if len(value) < 6 || strings.ContainsAny(value, "%_") {
			return nil, errors.New("give at least 6 hex characters of a SHA-256")
		}
		rows, err = d.sql.Query(base+"WHERE s.sha256 LIKE ? ESCAPE '\\' ORDER BY s.last_seen DESC LIMIT 200", strings.ToLower(value)+"%")
	case "ioc":
		rows, err = d.sql.Query(base+"WHERE s.sha256 IN (SELECT sha256 FROM features WHERE (kind LIKE 'indicator:%' AND value = ?) OR (kind = 'host' AND value = ?)) ORDER BY s.last_seen DESC LIMIT 200", value, strings.ToLower(value))
	default:
		rows, err = d.sql.Query(base+"WHERE s.sha256 IN (SELECT sha256 FROM features WHERE kind = ? AND value = ?) ORDER BY s.last_seen DESC LIMIT 200", kind, value)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []SampleRef
	for rows.Next() {
		var r SampleRef
		if err := rows.Scan(&r.SHA256, &r.Name, &r.FirstSeen, &r.LastSeen, &r.TimesSeen, &r.Format, &r.Packing); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Forget removes a sample and everything derived from it (analyses, features,
// case links). Notes attached to a case stay; their sample reference is cleared.
func (d *DB) Forget(sha string) (bool, error) {
	tx, err := d.sql.Begin()
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec("UPDATE notes SET sha256 = NULL WHERE sha256 = ?", sha); err != nil {
		_ = tx.Rollback()
		return false, err
	}
	res, err := tx.Exec("DELETE FROM samples WHERE sha256 = ?", sha)
	if err != nil {
		_ = tx.Rollback()
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, tx.Commit()
}

// SQL exposes the handle to the cases package.
func (d *DB) SQL() *sql.DB { return d.sql }

// Now is the timestamp format used throughout the database.
func Now() string { return now() }

// Package cases manages investigations: named groups of samples with notes
// and an automatic timeline, stored in the local database.
package cases

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/database"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// MaxNoteBytes bounds a note.
const MaxNoteBytes = 8000

// ErrNoCase and ErrNoSample are the "not found" errors.
var (
	ErrNoCase   = errors.New("no such case")
	ErrNoSample = errors.New("that sample has not been analysed yet")
)

// Case is a case's header.
type Case struct {
	ID                                   int64
	Name, Description, Status, CreatedAt string
	Samples                              int
}

func caseID(db *database.DB, name string) (int64, error) {
	var id int64
	err := db.SQL().QueryRow("SELECT id FROM cases WHERE name = ?", name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: %q", ErrNoCase, name)
	}
	return id, err
}

func event(tx *sql.Tx, caseID int64, kind, sha, detail string) error {
	var s any
	if sha != "" {
		s = sha
	}
	_, err := tx.Exec("INSERT INTO timeline(case_id, at, kind, sha256, detail) VALUES (?,?,?,?,?)", caseID, database.Now(), kind, s, detail)
	return err
}

// New creates a case.
func New(db *database.DB, name, description string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("case names are 1-64 characters: letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if len(description) > 500 {
		return errors.New("description is limited to 500 characters")
	}
	tx, err := db.SQL().Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec("INSERT INTO cases(name, description, created_at) VALUES (?,?,?)", name, description, database.Now())
	if err != nil {
		_ = tx.Rollback()
		if strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("a case named %q already exists", name)
		}
		return err
	}
	id, _ := res.LastInsertId()
	if err := event(tx, id, "case-created", "", "case opened"); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// List returns all cases, newest first.
func List(db *database.DB) ([]Case, error) {
	rows, err := db.SQL().Query(`SELECT c.id, c.name, c.description, c.status, c.created_at, (SELECT count(*) FROM case_samples cs WHERE cs.case_id = c.id)
		FROM cases c ORDER BY c.created_at DESC, c.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []Case
	for rows.Next() {
		var c Case
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Status, &c.CreatedAt, &c.Samples); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ResolveSample expands a SHA-256 prefix to a stored sample.
func ResolveSample(db *database.DB, prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 6 || !regexp.MustCompile(`^[0-9a-f]+$`).MatchString(prefix) {
		return "", errors.New("give at least 6 hex characters of a SHA-256")
	}
	rows, err := db.SQL().Query("SELECT sha256 FROM samples WHERE sha256 LIKE ? LIMIT 3", prefix+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var found []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return "", err
		}
		found = append(found, s)
	}
	switch len(found) {
	case 0:
		return "", ErrNoSample
	case 1:
		return found[0], nil
	}
	return "", errors.New("that prefix matches more than one sample; give more characters")
}

// AddSample links a stored sample to a case.
func AddSample(db *database.DB, name, sha string) error {
	id, err := caseID(db, name)
	if err != nil {
		return err
	}
	tx, err := db.SQL().Begin()
	if err != nil {
		return err
	}
	res, err := tx.Exec("INSERT OR IGNORE INTO case_samples(case_id, sha256, added_at) VALUES (?,?,?)", id, sha, database.Now())
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		if err := event(tx, id, "sample-added", sha, "sample added to the case"); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// AddNote records an analyst note, optionally about one sample.
func AddNote(db *database.DB, name, sha, body string) error {
	body = strings.TrimSpace(body)
	if body == "" {
		return errors.New("the note is empty")
	}
	if len(body) > MaxNoteBytes {
		return fmt.Errorf("notes are limited to %d bytes", MaxNoteBytes)
	}
	id, err := caseID(db, name)
	if err != nil {
		return err
	}
	tx, err := db.SQL().Begin()
	if err != nil {
		return err
	}
	var s any
	if sha != "" {
		s = sha
	}
	if _, err := tx.Exec("INSERT INTO notes(case_id, sha256, created_at, body) VALUES (?,?,?,?)", id, s, database.Now(), body); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := event(tx, id, "note", sha, "note added"); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SetStatus opens or closes a case.
func SetStatus(db *database.DB, name, status string) error {
	if status != "open" && status != "closed" {
		return errors.New("status must be open or closed")
	}
	id, err := caseID(db, name)
	if err != nil {
		return err
	}
	tx, err := db.SQL().Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE cases SET status = ? WHERE id = ?", status, id); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := event(tx, id, "case-"+status, "", "case "+status); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SearchHit is a note matching a search.
type SearchHit struct{ Case, At, SHA256, Body string }

// Search finds notes containing the given words. The query is quoted so
// operators typed by the user cannot break the FTS syntax.
func Search(db *database.DB, query string) ([]SearchHit, error) {
	q := `"` + strings.ReplaceAll(strings.TrimSpace(query), `"`, `""`) + `"`
	if q == `""` {
		return nil, errors.New("empty search")
	}
	rows, err := db.SQL().Query(`SELECT c.name, n.created_at, COALESCE(n.sha256,''), n.body FROM notes_fts f
		JOIN notes n ON n.id = f.rowid JOIN cases c ON c.id = n.case_id WHERE notes_fts MATCH ? ORDER BY n.created_at DESC LIMIT 100`, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close() //nolint:errcheck // read-only
	var out []SearchHit
	for rows.Next() {
		var h SearchHit
		if err := rows.Scan(&h.Case, &h.At, &h.SHA256, &h.Body); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// BuildReport assembles a case: its samples, indicators shared between them,
// notes and timeline.
func BuildReport(db *database.DB, name string) (*models.CaseReport, error) {
	id, err := caseID(db, name)
	if err != nil {
		return nil, err
	}
	r := &models.CaseReport{Name: name, Generated: database.Now(), Samples: []models.CaseSample{}, Indicators: []models.CaseIndicator{}, Notes: []models.CaseNote{}, Timeline: []models.CaseEvent{}}
	if err := db.SQL().QueryRow("SELECT description, status, created_at FROM cases WHERE id = ?", id).Scan(&r.Description, &r.Status, &r.CreatedAt); err != nil {
		return nil, err
	}
	rows, err := db.SQL().Query(`SELECT s.sha256, s.last_name, s.first_seen, s.last_seen,
		COALESCE(a.format,''), COALESCE(a.packing_state,''), COALESCE(a.language,''), COALESCE(a.findings,0), COALESCE(a.high,0), COALESCE(a.medium,0)
		FROM case_samples cs JOIN samples s ON s.sha256 = cs.sha256
		LEFT JOIN analyses a ON a.id = (SELECT max(id) FROM analyses WHERE sha256 = s.sha256)
		WHERE cs.case_id = ? ORDER BY cs.added_at, s.sha256`, id)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var s models.CaseSample
		if err := rows.Scan(&s.SHA256, &s.Name, &s.FirstSeen, &s.LastSeen, &s.Format, &s.Packing, &s.Language, &s.Findings, &s.High, &s.Medium); err != nil {
			_ = rows.Close()
			return nil, err
		}
		r.Samples = append(r.Samples, s)
	}
	_ = rows.Close()

	ir, err := db.SQL().Query(`SELECT CASE WHEN f.kind = 'host' THEN 'host' ELSE substr(f.kind, 11) END, f.value, f.sha256 FROM features f
		JOIN case_samples cs ON cs.sha256 = f.sha256 WHERE cs.case_id = ? AND (f.kind LIKE 'indicator:%' OR f.kind = 'host') ORDER BY f.kind, f.value, f.sha256`, id)
	if err != nil {
		return nil, err
	}
	idx := map[string]*models.CaseIndicator{}
	var order []string
	for ir.Next() {
		var typ, val, sha string
		if err := ir.Scan(&typ, &val, &sha); err != nil {
			_ = ir.Close()
			return nil, err
		}
		k := typ + "\x00" + val
		if idx[k] == nil {
			idx[k] = &models.CaseIndicator{Type: typ, Value: val}
			order = append(order, k)
		}
		idx[k].Samples = append(idx[k].Samples, sha)
	}
	_ = ir.Close()
	for _, k := range order {
		r.Indicators = append(r.Indicators, *idx[k])
	}

	nr, err := db.SQL().Query("SELECT created_at, COALESCE(sha256,''), body FROM notes WHERE case_id = ? ORDER BY created_at, id", id)
	if err != nil {
		return nil, err
	}
	for nr.Next() {
		var n models.CaseNote
		if err := nr.Scan(&n.At, &n.SHA256, &n.Body); err != nil {
			_ = nr.Close()
			return nil, err
		}
		r.Notes = append(r.Notes, n)
	}
	_ = nr.Close()

	tr, err := db.SQL().Query("SELECT at, kind, COALESCE(sha256,''), detail FROM timeline WHERE case_id = ? ORDER BY at, id", id)
	if err != nil {
		return nil, err
	}
	defer tr.Close() //nolint:errcheck // read-only
	for tr.Next() {
		var e models.CaseEvent
		if err := tr.Scan(&e.At, &e.Kind, &e.SHA256, &e.Detail); err != nil {
			return nil, err
		}
		r.Timeline = append(r.Timeline, e)
	}
	return r, tr.Err()
}

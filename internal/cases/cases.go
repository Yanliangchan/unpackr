// Package cases manages investigations: named groups of samples with notes
// and an automatic timeline, stored in the local database.
package cases

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

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

func find(db *database.DB, name string) (*database.CaseRec, error) {
	for _, c := range db.Index().Cases {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNoCase, name)
}

// New creates a case.
func New(db *database.DB, name, description string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("case names are 1-64 characters: letters, digits, '.', '_' or '-', starting with a letter or digit")
	}
	if len(description) > 500 {
		return errors.New("description is limited to 500 characters")
	}
	ix := db.Index()
	for _, c := range ix.Cases {
		if c.Name == name {
			return fmt.Errorf("a case named %q already exists", name)
		}
	}
	at := database.Now()
	c := &database.CaseRec{ID: ix.NextCase, Name: name, Description: description, Status: "open", CreatedAt: at}
	ix.NextCase++
	ix.Cases = append(ix.Cases, c)
	db.AddEvent(c.ID, at, "case-created", "", "case opened")
	return db.Flush()
}

// List returns all cases, newest first.
func List(db *database.DB) ([]Case, error) {
	var out []Case
	for _, c := range db.Index().Cases {
		out = append(out, Case{ID: c.ID, Name: c.Name, Description: c.Description, Status: c.Status, CreatedAt: c.CreatedAt, Samples: len(c.Samples)})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

var hexRe = regexp.MustCompile(`^[0-9a-f]+$`)

// ResolveSample expands a SHA-256 prefix to a stored sample.
func ResolveSample(db *database.DB, prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if len(prefix) < 6 || !hexRe.MatchString(prefix) {
		return "", errors.New("give at least 6 hex characters of a SHA-256")
	}
	var found []string
	for sha := range db.Index().Samples {
		if strings.HasPrefix(sha, prefix) {
			found = append(found, sha)
		}
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
	c, err := find(db, name)
	if err != nil {
		return err
	}
	if db.Index().Samples[sha] == nil {
		return ErrNoSample
	}
	for _, l := range c.Samples {
		if l.SHA256 == sha {
			return nil // idempotent
		}
	}
	at := database.Now()
	c.Samples = append(c.Samples, database.CaseLink{SHA256: sha, AddedAt: at})
	db.AddEvent(c.ID, at, "sample-added", sha, "sample added to the case")
	return db.Flush()
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
	c, err := find(db, name)
	if err != nil {
		return err
	}
	ix := db.Index()
	at := database.Now()
	ix.Notes = append(ix.Notes, database.Note{ID: ix.NextNote, CaseID: c.ID, SHA256: sha, At: at, Body: body})
	ix.NextNote++
	db.AddEvent(c.ID, at, "note", sha, "note added")
	return db.Flush()
}

// SetStatus opens or closes a case.
func SetStatus(db *database.DB, name, status string) error {
	if status != "open" && status != "closed" {
		return errors.New("status must be open or closed")
	}
	c, err := find(db, name)
	if err != nil {
		return err
	}
	c.Status = status
	db.AddEvent(c.ID, database.Now(), "case-"+status, "", "case "+status)
	return db.Flush()
}

// SearchHit is a note matching a search.
type SearchHit struct{ Case, At, SHA256, Body string }

// maxSearchHits bounds a note search.
const maxSearchHits = 100

// words lower-cases text and splits it into letter/digit runs, the way the
// search compares them: punctuation and case never matter.
func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
}

func containsRun(hay, needle []string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		ok := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// Search finds notes containing the given words as a phrase. It is plain
// text matching, so operators typed by the user mean nothing.
func Search(db *database.DB, query string) ([]SearchHit, error) {
	if strings.TrimSpace(query) == "" {
		return nil, errors.New("empty search")
	}
	needle := words(query)
	if len(needle) == 0 {
		return nil, nil
	}
	ix := db.Index()
	names := map[int64]string{}
	for _, c := range ix.Cases {
		names[c.ID] = c.Name
	}
	var notes []database.Note
	for _, n := range ix.Notes {
		if _, ok := names[n.CaseID]; ok && containsRun(words(n.Body), needle) {
			notes = append(notes, n)
		}
	}
	sort.SliceStable(notes, func(i, j int) bool {
		if notes[i].At != notes[j].At {
			return notes[i].At > notes[j].At
		}
		return notes[i].ID > notes[j].ID
	})
	if len(notes) > maxSearchHits {
		notes = notes[:maxSearchHits]
	}
	var out []SearchHit
	for _, n := range notes {
		out = append(out, SearchHit{Case: names[n.CaseID], At: n.At, SHA256: n.SHA256, Body: n.Body})
	}
	return out, nil
}

// BuildReport assembles a case: its samples, indicators shared between them,
// notes and timeline.
func BuildReport(db *database.DB, name string) (*models.CaseReport, error) {
	c, err := find(db, name)
	if err != nil {
		return nil, err
	}
	ix := db.Index()
	r := &models.CaseReport{Name: name, Generated: database.Now(), Description: c.Description, Status: c.Status, CreatedAt: c.CreatedAt,
		Samples: []models.CaseSample{}, Indicators: []models.CaseIndicator{}, Notes: []models.CaseNote{}, Timeline: []models.CaseEvent{}}

	links := append([]database.CaseLink(nil), c.Samples...)
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].AddedAt != links[j].AddedAt {
			return links[i].AddedAt < links[j].AddedAt
		}
		return links[i].SHA256 < links[j].SHA256
	})
	for _, l := range links {
		s := ix.Samples[l.SHA256]
		if s == nil {
			continue
		}
		cs := models.CaseSample{SHA256: s.SHA256, Name: s.LastName, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen}
		if as := ix.Analyses[s.SHA256]; len(as) > 0 {
			a := as[len(as)-1]
			cs.Format, cs.Packing, cs.Language = a.Format, a.PackingState, a.Language
			cs.Findings, cs.High, cs.Medium = a.Findings, a.High, a.Medium
		}
		r.Samples = append(r.Samples, cs)
	}

	type row struct{ kind, typ, val, sha string }
	var rows []row
	for _, l := range links {
		for _, f := range ix.Features[l.SHA256] {
			switch {
			case f[0] == "host":
				rows = append(rows, row{f[0], "host", f[1], l.SHA256})
			case strings.HasPrefix(f[0], "indicator:"):
				rows = append(rows, row{f[0], strings.TrimPrefix(f[0], "indicator:"), f[1], l.SHA256})
			}
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		if a.val != b.val {
			return a.val < b.val
		}
		return a.sha < b.sha
	})
	idx := map[string]*models.CaseIndicator{}
	var order []string
	for _, x := range rows {
		k := x.typ + "\x00" + x.val
		if idx[k] == nil {
			idx[k] = &models.CaseIndicator{Type: x.typ, Value: x.val}
			order = append(order, k)
		}
		idx[k].Samples = append(idx[k].Samples, x.sha)
	}
	for _, k := range order {
		r.Indicators = append(r.Indicators, *idx[k])
	}

	for _, n := range ix.Notes {
		if n.CaseID == c.ID {
			r.Notes = append(r.Notes, models.CaseNote{At: n.At, SHA256: n.SHA256, Body: n.Body})
		}
	}
	sort.SliceStable(r.Notes, func(i, j int) bool { return r.Notes[i].At < r.Notes[j].At })
	for _, e := range ix.Timeline {
		if e.CaseID == c.ID {
			r.Timeline = append(r.Timeline, models.CaseEvent{At: e.At, Kind: e.Kind, SHA256: e.SHA256, Detail: e.Detail})
		}
	}
	sort.SliceStable(r.Timeline, func(i, j int) bool { return r.Timeline[i].At < r.Timeline[j].At })
	return r, nil
}

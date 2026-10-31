// Package artvault is the banner library. It is deliberately independent of
// the analysis engine: it imports nothing from the rest of the project except
// the embedded assets.
package artvault

import (
	"bufio"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Limits applied to every banner, built-in or custom.
const (
	MaxCols  = 80
	MaxRows  = 24
	MaxBytes = 4096
)

// Banner is one piece of artwork.
type Banner struct {
	ID       string
	Category string
	Title    string
	Lines    []string
	Custom   bool
}

// Text returns the artwork.
func (b Banner) Text() string { return strings.Join(b.Lines, "\n") }

// Validate enforces dimensions and character restrictions. In particular it
// rejects ESC and every other control byte so artwork can never carry
// terminal control sequences.
func Validate(b Banner) error {
	if b.ID == "" {
		return fmt.Errorf("missing id")
	}
	if len(b.Lines) == 0 {
		return fmt.Errorf("banner %s is empty", b.ID)
	}
	if len(b.Lines) > MaxRows {
		return fmt.Errorf("banner %s has %d rows (max %d)", b.ID, len(b.Lines), MaxRows)
	}
	total := 0
	for i, l := range b.Lines {
		total += len(l) + 1
		if len(l) > MaxCols {
			return fmt.Errorf("banner %s line %d is %d columns (max %d)", b.ID, i+1, len(l), MaxCols)
		}
		for j := 0; j < len(l); j++ {
			if l[j] < 0x20 || l[j] > 0x7e {
				return fmt.Errorf("banner %s line %d byte %d: 0x%02x is not printable ASCII", b.ID, i+1, j+1, l[j])
			}
		}
	}
	if total > MaxBytes {
		return fmt.Errorf("banner %s is %d bytes (max %d)", b.ID, total, MaxBytes)
	}
	return nil
}

// Parse reads the optional front matter ("---", key: value lines, "---") and
// the artwork. Files without front matter are accepted for custom artwork.
func Parse(name string, data []byte, custom bool) (Banner, error) {
	b := Banner{ID: strings.TrimSuffix(filepath.Base(name), filepath.Ext(name)), Category: "custom", Custom: custom}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 8192), MaxBytes*2)
	var lines []string
	for sc.Scan() {
		lines = append(lines, strings.TrimRight(sc.Text(), "\r"))
	}
	if err := sc.Err(); err != nil {
		return b, err
	}
	if len(lines) > 0 && lines[0] == "---" {
		end := -1
		for i := 1; i < len(lines); i++ {
			if lines[i] == "---" {
				end = i
				break
			}
		}
		if end < 0 {
			return b, fmt.Errorf("%s: unterminated front matter", name)
		}
		for _, l := range lines[1:end] {
			k, v, ok := strings.Cut(l, ":")
			if !ok {
				return b, fmt.Errorf("%s: bad front matter line %q", name, l)
			}
			v = strings.TrimSpace(v)
			switch strings.TrimSpace(k) {
			case "id":
				b.ID = v
			case "category":
				b.Category = v
			case "title":
				b.Title = v
			}
		}
		lines = lines[end+1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	b.Lines = lines
	return b, Validate(b)
}

// Vault is a loaded collection.
type Vault struct {
	banners []Banner
}

// Load reads built-in artwork from fsys and, if customDir is non-empty and
// exists, custom artwork. Invalid custom files are returned as errors but do
// not prevent the rest from loading. A built-in error is fatal.
func Load(fsys fs.FS, dir, customDir string) (*Vault, []error, error) {
	v := &Vault{}
	seen := map[string]bool{}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		data, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, nil, err
		}
		b, err := Parse(e.Name(), data, false)
		if err != nil {
			return nil, nil, fmt.Errorf("built-in artwork %s: %w", e.Name(), err)
		}
		if seen[b.ID] {
			return nil, nil, fmt.Errorf("duplicate built-in id %s", b.ID)
		}
		seen[b.ID] = true
		v.banners = append(v.banners, b)
	}
	var warns []error
	if customDir != "" {
		ents, err := os.ReadDir(customDir)
		if err == nil {
			for _, e := range ents {
				if e.IsDir() || !strings.HasSuffix(e.Name(), ".txt") {
					continue
				}
				p := filepath.Join(customDir, e.Name())
				st, err := os.Lstat(p)
				if err != nil || !st.Mode().IsRegular() || st.Size() > MaxBytes*2 {
					warns = append(warns, fmt.Errorf("%s: skipped (not a regular file under %d bytes)", p, MaxBytes*2))
					continue
				}
				data, err := os.ReadFile(p)
				if err != nil {
					warns = append(warns, err)
					continue
				}
				b, err := Parse(e.Name(), data, true)
				if err != nil {
					warns = append(warns, fmt.Errorf("%s: %w", p, err))
					continue
				}
				if seen[b.ID] {
					warns = append(warns, fmt.Errorf("%s: id %q already in use", p, b.ID))
					continue
				}
				seen[b.ID] = true
				v.banners = append(v.banners, b)
			}
		}
	}
	sort.Slice(v.banners, func(i, j int) bool { return v.banners[i].ID < v.banners[j].ID })
	return v, warns, nil
}

// All returns the banners sorted by id.
func (v *Vault) All() []Banner { return v.banners }

// Categories returns category names with counts.
func (v *Vault) Categories() map[string]int {
	m := map[string]int{}
	for _, b := range v.banners {
		m[b.Category]++
	}
	return m
}

// Get finds a banner by id.
func (v *Vault) Get(id string) (Banner, bool) {
	for _, b := range v.banners {
		if b.ID == id {
			return b, true
		}
	}
	return Banner{}, false
}

// Pick resolves a selector: "random", an id, or a category name. For random
// and category selection the previously shown banner is avoided when any
// alternative exists.
func (v *Vault) Pick(selector, last string, rnd *rand.Rand) (Banner, error) {
	if len(v.banners) == 0 {
		return Banner{}, fmt.Errorf("no artwork available")
	}
	if selector == "" || selector == "random" {
		return v.choose(v.banners, last, rnd), nil
	}
	if b, ok := v.Get(selector); ok {
		return b, nil
	}
	var pool []Banner
	for _, b := range v.banners {
		if b.Category == selector {
			pool = append(pool, b)
		}
	}
	if len(pool) == 0 {
		return Banner{}, fmt.Errorf("no banner or category named %q", selector)
	}
	return v.choose(pool, last, rnd), nil
}

func (v *Vault) choose(pool []Banner, last string, rnd *rand.Rand) Banner {
	cand := pool
	if len(pool) > 1 {
		cand = nil
		for _, b := range pool {
			if b.ID != last {
				cand = append(cand, b)
			}
		}
	}
	return cand[rnd.Intn(len(cand))]
}

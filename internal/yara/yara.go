// Package yara runs YARA-X (the `yr` command) over a sample and turns its
// output into structured matches. The engine is optional; without it UNPACKR
// uses its native detectors only and says so.
//
// Safety: rules are plain text, the sample is a private copy, and `yr` runs in
// the confined exec worker (no network, writes only to a private directory).
// Its output is untrusted: it is parsed strictly, bounded, and every string in
// it is sanitised before display.
package yara

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits on what is read from rules and from the tool.
const (
	MaxUserRuleFiles = 50
	MaxUserRuleBytes = 256 << 10
	MaxMatches       = 500
	MaxStringsPerHit = 16
	MaxMatchData     = 64
	MaxOutputLines   = 4
)

var reVersion = regexp.MustCompile(`(\d+\.\d+\.\d+)`)

// Options for one scan.
type Options struct {
	Builtin     fs.FS  // embedded rule files
	BuiltinDir  string // directory inside Builtin
	UserRuleDir string // optional directory of analyst rules
	Timeout     time.Duration
	MemoryBytes uint64
}

// Result is a scan outcome.
type Result struct {
	Matches []models.YaraMatch
	Engine  models.EngineStatus
}

// Locate finds yr and reads its version inside the sandbox.
func Locate(ctx context.Context, name string, mem uint64) (*unpacking.Tool, error) {
	if name == "" {
		name = "yr"
	}
	t, err := unpacking.Locate(name)
	if err != nil {
		return nil, err
	}
	work, err := unpacking.WorkDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir
	res, err := worker.RunExec(ctx, t.Spec(work, []string{"--version"}, mem, 1<<20), 20*time.Second)
	if err != nil {
		return t, err
	}
	if m := reVersion.FindString(res.Stdout + res.Stderr); m != "" {
		t.Version = m
	}
	return t, nil
}

// Scan copies sample into a private directory, stages the rules and runs yr.
func Scan(ctx context.Context, t *unpacking.Tool, sample io.Reader, o Options) (*Result, error) {
	res := &Result{Engine: models.EngineStatus{Name: "YARA-X", Version: t.Version}}
	work, err := unpacking.WorkDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir

	target := filepath.Join(work, "target.bin")
	if err := writeNew(target, sample); err != nil {
		return nil, fmt.Errorf("staging sample: %w", err)
	}
	builtin := filepath.Join(work, "builtin")
	if err := stageBuiltin(o.Builtin, o.BuiltinDir, builtin); err != nil {
		return nil, fmt.Errorf("staging built-in rules: %w", err)
	}
	args := []string{"scan", "-o", "ndjson", "-s", "-m", "-g", "-e", "--max-matches-per-pattern", "8",
		"--disable-console-logs", "-w", "--ignore-invalid-rules", "builtin:" + builtin}
	userStaged, skipped := 0, 0
	if o.UserRuleDir != "" {
		user := filepath.Join(work, "user")
		userStaged, skipped, err = stageUser(o.UserRuleDir, user)
		if err != nil {
			return nil, err
		}
		if userStaged > 0 {
			args = append(args, "user:"+user)
		}
	}
	args = append(args, target)

	run, err := worker.RunExec(ctx, t.Spec(work, args, o.MemoryBytes, 1<<20), o.Timeout)
	if err != nil {
		return nil, err
	}
	if run.ExitCode != 0 {
		return nil, fmt.Errorf("yr exited with status %d: %s", run.ExitCode, firstLines(run.Stderr))
	}
	res.Matches, err = Parse(run.Stdout)
	if err != nil {
		return nil, err
	}
	res.Engine.Status = "used"
	if userStaged > 0 {
		res.Engine.Detail = fmt.Sprintf("%d analyst rule file(s) loaded", userStaged)
	}
	if skipped > 0 {
		res.Engine.Detail += fmt.Sprintf("; %d analyst rule file(s) skipped (too large, too many, or not regular files)", skipped)
	}
	return res, nil
}

type rawLine struct {
	Rules []rawRule `json:"rules"`
}

type rawRule struct {
	Identifier string               `json:"identifier"`
	Namespace  string               `json:"namespace"`
	Meta       [][2]json.RawMessage `json:"meta"`
	Tags       []string             `json:"tags"`
	Strings    []struct {
		Identifier string `json:"identifier"`
		Offset     int64  `json:"offset"`
		Match      string `json:"match"`
	} `json:"strings"`
}

// Parse decodes yr's ndjson output. It is strict and bounded because the
// bytes come from a process that has just parsed hostile data.
func Parse(out string) ([]models.YaraMatch, error) {
	var matches []models.YaraMatch
	lines := 0
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if lines++; lines > MaxOutputLines {
			return nil, fmt.Errorf("unexpected yr output: more than %d result lines for one file", MaxOutputLines)
		}
		var rl rawLine
		if err := json.Unmarshal([]byte(l), &rl); err != nil {
			return nil, fmt.Errorf("unexpected yr output: %w", err)
		}
		for _, r := range rl.Rules {
			if len(matches) >= MaxMatches {
				return matches, nil
			}
			m := models.YaraMatch{Rule: textutil.Sanitize(clip(r.Identifier, 128)), Namespace: textutil.Sanitize(clip(r.Namespace, 32))}
			if len(r.Tags) > 0 {
				m.Category = textutil.Sanitize(clip(r.Tags[0], 48))
			}
			for _, kv := range r.Meta {
				var k string
				if json.Unmarshal(kv[0], &k) != nil {
					continue
				}
				var v string
				if json.Unmarshal(kv[1], &v) != nil {
					continue // numeric and boolean metadata are not used
				}
				v = textutil.Sanitize(clip(v, 200))
				switch k {
				case "name":
					m.Name = v
				case "description":
					m.Description = v
				case "strength":
					m.Strength = v
				case "family":
					m.Family = v
				case "status":
					m.Status = v
				}
			}
			for i, s := range r.Strings {
				if i >= MaxStringsPerHit {
					break
				}
				m.Matches = append(m.Matches, models.YaraString{
					Identifier: textutil.Sanitize(clip(s.Identifier, 64)), Offset: s.Offset, Length: len(s.Match),
					Data: textutil.Sanitize(clip(s.Match, MaxMatchData)),
				})
			}
			classify(&m)
			matches = append(matches, m)
		}
	}
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].Rule < matches[j].Rule })
	return matches, nil
}

// classify decides how far a match may be trusted. Only built-in rules
// declared "tested" are evidence; analyst rules are shown but never counted.
func classify(m *models.YaraMatch) {
	switch m.Namespace {
	case "builtin":
		if m.Status != "tested" {
			m.Status = "experimental"
		}
		if m.Strength != "strong" && m.Strength != "moderate" && m.Strength != "weak" {
			m.Strength = "weak"
		}
	default:
		m.Namespace = "user"
		m.Status = "user"
		m.Strength, m.Family = "", ""
	}
	if m.Name == "" {
		m.Name = m.Rule
	}
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func firstLines(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, strings.TrimSpace(l))
		}
		if len(out) == 2 {
			break
		}
	}
	return textutil.Sanitize(clip(strings.Join(out, " | "), 300))
}

func writeNew(path string, r io.Reader) error {
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func stageBuiltin(fsys fs.FS, dir, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yar") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// stageUser copies analyst rule files into the private directory, enforcing
// count, size and file-type limits. Symlinks are never followed.
func stageUser(src, dst string) (staged, skipped int, err error) {
	ents, rerr := os.ReadDir(src)
	if rerr != nil {
		return 0, 0, nil // no directory is not an error
	}
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".yar") && !strings.HasSuffix(name, ".yara") {
			continue
		}
		p := filepath.Join(src, name)
		st, serr := os.Lstat(p)
		if serr != nil || !st.Mode().IsRegular() || st.Size() > MaxUserRuleBytes || staged >= MaxUserRuleFiles {
			skipped++
			continue
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			skipped++
			continue
		}
		// Rule files are staged under index names so file names from the
		// analyst's directory never become paths in the sandbox.
		if err := os.WriteFile(filepath.Join(dst, fmt.Sprintf("rules%02d.yar", staged)), b, 0o600); err != nil {
			return staged, skipped, err
		}
		staged++
	}
	return staged, skipped, nil
}

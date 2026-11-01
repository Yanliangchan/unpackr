// Package reverse runs radare2 on a sample, inside the exec sandbox, to answer
// a question the import table alone cannot: where in the code is an imported
// API actually referenced?
//
// It is an adapter, not an analysis engine: it builds one fixed command script,
// runs it, and parses the output strictly. The sample is hostile, and so is
// everything radare2 prints about it.
//
// Two defences matter more than the rest:
//
//   - radare2's command language has a shell escape, backtick substitution,
//     redirection and command separators. The only values placed in the script
//     are API names taken from the sample's own import table, and only after they
//     match a strict allow-list (letters, digits, underscore, dot, dollar).
//     Anything else is skipped, never quoted. This is the defence that matters:
//     radare2's own sandbox setting (cfg.sandbox) blocks a leading "!", pipes,
//     file writes and scripts, but a "!" inside backticks still ran when this was
//     tested on 5.5.0, so it is only a second line.
//   - radare2 runs inside the process sandbox (Landlock, seccomp, no network, one
//     writable scratch directory), so even a command that got through could not
//     reach anything of value.
//
// Verified against radare2 5.5.0 on ELF and PE. Other versions use the same
// command names but their output formats are not checked here, and Rizin is not
// supported.
package reverse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Limits.
const (
	MaxSampleBytes   = 64 << 20
	MaxAPIs          = 40
	MaxCallSites     = 200
	maxPerAPI        = 10
	maxLargest       = 10
	outputCap        = 1 << 20 // the exec worker's stdout cap
	maxFunctionLines = 200000
)

// ToolNames are tried in order.
var ToolNames = []string{"radare2", "r2"}

// API is an imported function to look up.
type API struct {
	Name    string
	Library string // PE only
}

var (
	reSafeName = regexp.MustCompile(`^[A-Za-z0-9_.$]{1,128}$`)
	reSafeLib  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	reAnsi     = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)
	reVersion  = regexp.MustCompile(`radare2 (\d+\.\d+\.\d+)`)
)

// flagFor returns the radare2 flag for an import, or false when the name is not
// safe to put in a command. The flag names are radare2's: ELF imports are
// sym.imp.NAME and PE imports sym.imp.LIB.dll_NAME.
func flagFor(a API, family string) (string, bool) {
	if !reSafeName.MatchString(a.Name) {
		return "", false
	}
	switch family {
	case "elf":
		return "sym.imp." + a.Name, true
	case "pe":
		if !reSafeLib.MatchString(a.Library) {
			return "", false
		}
		return "sym.imp." + a.Library + "_" + a.Name, true
	}
	return "", false
}

// script builds the command script. Section markers separate the outputs.
//
// The markers are plain words carrying a random token, because radare2 treats
// ">>" as a redirection and the output includes names taken from the sample: a
// section break must not be forgeable from inside the file.
func script(flags []string, token string) string {
	m := func(k string) string { return "?e " + marker(token, k) }
	var b strings.Builder
	// The sandbox setting goes on after the sample is open: set earlier, radare2
	// cannot open the file at all.
	// "aa" alone follows only the entry point and named symbols: on a stripped
	// program it finds a handful of functions (2 in a 656 KB sample where "aa;aac"
	// finds 1,092). "aac" adds functions reached by calls. "aaa" finds the same
	// functions and is several times slower.
	b.WriteString("e cfg.sandbox=true;aa;aac;" + m("I") + ";iIj;" + m("E") + ";iej;" + m("F") + ";afl")
	for i, f := range flags {
		fmt.Fprintf(&b, ";%s;axtj %s", m(fmt.Sprintf("X%d", i)), f)
	}
	return b.String()
}

func marker(token, key string) string { return "UNPACKR" + token + "END" + key }

func newToken() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Options for one run.
type Options struct {
	Timeout     time.Duration
	MemoryBytes uint64
}

// Locate finds radare2 and reads its version inside the sandbox.
func Locate(ctx context.Context, mem uint64) (*unpacking.Tool, error) {
	var last error
	for _, n := range ToolNames {
		t, err := unpacking.Locate(n)
		if err != nil {
			last = err
			continue
		}
		work, err := unpacking.WorkDir()
		if err != nil {
			return nil, err
		}
		res, err := worker.RunExec(ctx, t.Spec(work, []string{"-v"}, mem, 1<<20), 20*time.Second)
		_ = os.RemoveAll(work)
		if err != nil {
			return t, err
		}
		if m := reVersion.FindStringSubmatch(res.Stdout + res.Stderr); m != nil {
			t.Version = m[1]
		}
		return t, nil
	}
	return nil, last
}

// Run analyses the sample and looks up the given imports. family is "elf" or
// "pe"; other formats are skipped by the caller.
func Run(ctx context.Context, t *unpacking.Tool, sample io.Reader, family string, apis []API, o Options) (*models.Reverse, error) {
	res := &models.Reverse{Engine: "radare2", Version: t.Version}
	work, err := unpacking.WorkDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir

	target := filepath.Join(work, "target.bin")
	if err := writeNew(target, io.LimitReader(sample, MaxSampleBytes+1)); err != nil {
		return nil, fmt.Errorf("staging sample: %w", err)
	}
	if st, err := os.Stat(target); err == nil && st.Size() > MaxSampleBytes {
		res.Skipped = fmt.Sprintf("the file is larger than %d MiB; radare2 analysis is bounded", MaxSampleBytes>>20)
		return res, nil
	}

	var flags []string
	var used []API
	skipped := 0
	for _, a := range apis {
		if len(flags) >= MaxAPIs {
			break
		}
		f, ok := flagFor(a, family)
		if !ok {
			skipped++
			continue
		}
		flags = append(flags, f)
		used = append(used, a)
	}
	if skipped > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d import name(s) were not looked up because they contain characters that are not safe to pass to radare2", skipped))
	}

	token, err := newToken()
	if err != nil {
		return nil, err
	}
	args := []string{"-q", "-N", "-e", "scr.color=0", "-e", "scr.interactive=false", "-e", "bin.cache=true", "-c", script(flags, token), target}
	spec := t.Spec(work, args, o.MemoryBytes, 1<<20)
	for _, d := range []string{"/usr/share/radare2", "/usr/local/share/radare2"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			spec.ReadOnly = append(spec.ReadOnly, d)
		}
	}
	run, err := worker.RunExec(ctx, spec, o.Timeout)
	if err != nil {
		return nil, err
	}
	if run.ExitCode != 0 {
		return nil, fmt.Errorf("radare2 exited with status %d: %s", run.ExitCode, firstLine(run.Stderr))
	}
	if len(run.Stdout) >= outputCap {
		res.Truncated = true
		res.Notes = append(res.Notes, "radare2's output was cut at 1 MiB, so the function list may be incomplete")
	}
	if err := parse(res, run.Stdout, token, used, flags); err != nil {
		return nil, err
	}
	return res, nil
}

// split cuts the output at the marker lines. A marker is a whole line carrying
// this run's token.
func split(out, token string) map[string]string {
	out = reAnsi.ReplaceAllString(out, "")
	prefix := marker(token, "")
	parts := map[string]string{}
	cur := ""
	var b strings.Builder
	flush := func() {
		if cur != "" {
			parts[cur] = b.String()
		}
		b.Reset()
	}
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, prefix) && len(t) <= len(prefix)+8 {
			flush()
			cur = t[len(prefix):]
			continue
		}
		if cur != "" {
			b.WriteString(l)
			b.WriteByte('\n')
		}
	}
	flush()
	return parts
}

// lastJSON returns the last line that starts a JSON array or object.
func lastJSON(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.HasPrefix(l, "[") || strings.HasPrefix(l, "{") {
			return l
		}
	}
	return ""
}

func parse(res *models.Reverse, out, token string, used []API, flags []string) error {
	parts := split(out, token)
	if _, ok := parts["F"]; !ok {
		return errors.New("unexpected radare2 output: the function listing is missing")
	}

	// Functions: "0x... nbbs size name" per line.
	type fn struct {
		va         uint64
		blocks, sz int
		name       string
	}
	var fns []fn
	for i, l := range strings.Split(parts["F"], "\n") {
		if i >= maxFunctionLines {
			res.Truncated = true
			break
		}
		f := strings.Fields(l)
		// "0x1150  4 41 -> 34 name": radare2 adds "-> <real size>" when the
		// function is smaller than its bounds.
		if len(f) >= 6 && f[3] == "->" {
			f = append(f[:3:3], f[5:]...)
		}
		if len(f) < 4 || !strings.HasPrefix(f[0], "0x") {
			continue
		}
		va, err := strconv.ParseUint(f[0][2:], 16, 64)
		if err != nil {
			continue
		}
		nb, err1 := strconv.Atoi(f[1])
		sz, err2 := strconv.Atoi(f[2])
		if err1 != nil || err2 != nil || nb < 0 || sz < 0 {
			continue
		}
		fns = append(fns, fn{va, nb, sz, textutil.Sanitize(clip(strings.Join(f[3:], " "), 120))})
	}
	res.Functions = len(fns)

	// Entry point: the function that starts at the first entry address.
	if js := lastJSON(parts["E"]); js != "" {
		var entries []struct {
			Vaddr uint64 `json:"vaddr"`
		}
		if json.Unmarshal([]byte(js), &entries) == nil && len(entries) > 0 {
			for _, f := range fns {
				if f.va == entries[0].Vaddr {
					res.Entry = f.name
					break
				}
			}
		}
	}

	sort.SliceStable(fns, func(i, j int) bool { return fns[i].sz > fns[j].sz })
	for i := 0; i < len(fns) && i < maxLargest; i++ {
		res.Largest = append(res.Largest, models.ReverseFunc{Name: fns[i].name, VA: fns[i].va, Size: fns[i].sz, Blocks: fns[i].blocks})
	}

	// References to imports.
	more := 0
	for i := range flags {
		js := lastJSON(parts[fmt.Sprintf("X%d", i)])
		if js == "" {
			continue
		}
		var refs []struct {
			From    uint64 `json:"from"`
			Type    string `json:"type"`
			FcnAddr uint64 `json:"fcn_addr"`
			FcnName string `json:"fcn_name"`
			Name    string `json:"name"`
		}
		if json.Unmarshal([]byte(js), &refs) != nil {
			continue
		}
		kept := 0
		for _, r := range refs {
			if kept >= maxPerAPI || len(res.CallSites) >= MaxCallSites {
				more++
				continue
			}
			kind := map[string]string{"CALL": "call", "CODE": "jump", "DATA": "data"}[r.Type]
			if kind == "" {
				kind = "data"
			}
			where := r.FcnName
			if where == "" {
				where = r.Name // a reference from a thunk that is not a discovered function
			}
			res.CallSites = append(res.CallSites, models.ReverseCall{
				API: used[i].Name, Library: used[i].Library, Function: textutil.Sanitize(clip(strings.TrimPrefix(where, "sym."), 120)),
				FuncVA: r.FcnAddr, At: r.From, Kind: kind,
			})
			kept++
		}
	}
	if more > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%d further reference(s) were not listed (at most %d per API and %d in total)", more, maxPerAPI, MaxCallSites))
	}
	sort.SliceStable(res.CallSites, func(i, j int) bool {
		if res.CallSites[i].API != res.CallSites[j].API {
			return res.CallSites[i].API < res.CallSites[j].API
		}
		return res.CallSites[i].At < res.CallSites[j].At
	})
	return nil
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(textutil.Sanitize(s))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return clip(s, 200)
}

func writeNew(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func newResult() *models.Reverse { return &models.Reverse{Engine: "radare2"} }

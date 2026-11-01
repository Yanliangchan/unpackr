package similarity

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Yanliangchan/unpackr/pkg/models"
	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

func randomBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

// text-like data with structure, so fuzzy hashes have something to hold on to.
func structured(seed int64, n int) []byte {
	r := rand.New(rand.NewSource(seed))
	words := []string{"alpha", "beta", "gamma", "delta", "kernel32", "CreateFileW", "http", "config", "update", "runtime"}
	var b bytes.Buffer
	for b.Len() < n {
		b.WriteString(words[r.Intn(len(words))])
		b.WriteByte(byte(r.Intn(40) + 1))
		b.Write(randomBytes(r.Int63(), r.Intn(5)))
	}
	return b.Bytes()[:n]
}

func mutate(b []byte, frac float64, seed int64) []byte {
	out := append([]byte(nil), b...)
	r := rand.New(rand.NewSource(seed))
	for i := 0; i < int(float64(len(out))*frac); i++ {
		out[r.Intn(len(out))] = byte(r.Intn(256))
	}
	return out
}

// mutateBlock overwrites one contiguous region, the kind of change ssdeep
// (whose signatures are built from rolling windows) is designed to survive.
func mutateBlock(b []byte, frac float64, seed int64) []byte {
	out := append([]byte(nil), b...)
	n := int(float64(len(out)) * frac)
	start := len(out) / 3
	copy(out[start:start+n], randomBytes(seed, n))
	return out
}

func TestHashFormatsAndLimits(t *testing.T) {
	ssd, tl := Hash(structured(1, 100000))
	if !strings.Contains(ssd, ":") || !strings.HasPrefix(tl, "T1") || len(tl) != 72 || tl != strings.ToUpper(tl) {
		t.Fatalf("ssdeep=%q tlsh=%q", ssd, tl)
	}
	if _, tl := Hash([]byte("short")); tl != "" {
		t.Fatal("TLSH must be empty for inputs below its minimum size")
	}
	if ssd, tl := Hash(nil); ssd != "" && tl != "" {
		t.Fatalf("%q %q", ssd, tl)
	}
	if _, tl := Hash(bytes.Repeat([]byte{7}, 100000)); tl != "" && len(tl) != 72 {
		t.Fatalf("malformed %q", tl)
	}
}

func TestComparisonsAreSaneAndSymmetric(t *testing.T) {
	a := structured(2, 200000)
	sa, ta := Hash(a)
	sb, tb := Hash(mutateBlock(a, 0.03, 3))
	sc, tc := Hash(structured(99, 200000))

	if d, ok := DiffTLSH(ta, ta); !ok || d != 0 {
		t.Fatalf("self distance %d %v", d, ok)
	}
	near, _ := DiffTLSH(ta, tb)
	far, _ := DiffTLSH(ta, tc)
	if near >= far {
		t.Fatalf("a 3%% edited block (%d) must be closer than unrelated data (%d)", near, far)
	}
	back, _ := DiffTLSH(tb, ta)
	if back != near {
		t.Fatalf("TLSH distance not symmetric: %d vs %d", near, back)
	}
	if s, ok := CompareSSDeep(sa, sa); !ok || s != 100 {
		t.Fatalf("%d %v", s, ok)
	}
	n, _ := CompareSSDeep(sa, sb)
	f, _ := CompareSSDeep(sa, sc)
	if n <= f {
		t.Fatalf("ssdeep: an edited block (%d) should score above unrelated data (%d)", n, f)
	}
	// Bad input is "not comparable", never a panic or a made-up number.
	for _, bad := range []string{"", "T1", "T1zz", "T1" + strings.Repeat("0", 69), "not a hash", strings.Repeat("A", 500), "T1" + strings.Repeat("G", 70)} {
		if _, ok := DiffTLSH(bad, ta); ok {
			t.Errorf("malformed TLSH %q accepted", bad)
		}
		if _, ok := CompareSSDeep(bad, sa); ok && bad != sa {
			t.Errorf("malformed ssdeep %q accepted", bad)
		}
	}
	// Signatures of incomparable block sizes simply do not match.
	if sc, ok := CompareSSDeep("3:abcdefg:def", "3072:abcdefg:def"); !ok || sc != 0 {
		t.Errorf("incomparable block sizes: score %d ok %v", sc, ok)
	}
}

// The central validation: our Go ports produce exactly what the reference
// implementations produce. Skipped when a reference tool is not installed.
func TestMatchesReferenceImplementations(t *testing.T) {
	ssdeepBin, err := exec.LookPath("ssdeep")
	if err != nil {
		t.Skip("reference ssdeep not installed")
	}
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	if err := exec.Command(py, "-c", "import tlsh").Run(); err != nil { //nolint:gosec // fixed test tool
		t.Skip("reference py-tlsh not installed")
	}
	dir := t.TempDir()
	var files []string
	base := structured(7, 300000)
	for i, d := range [][]byte{base, mutate(base, 0.02, 1), mutate(base, 0.15, 2), structured(8, 150000), randomBytes(9, 60000), mutate(base[:100000], 0.01, 3), mutateBlock(base, 0.03, 4), mutateBlock(base, 0.2, 5)} {
		p := filepath.Join(dir, "f"+strconv.Itoa(i))
		if err := os.WriteFile(p, d, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	files = append(files, fixtures.GoBinary(t, "linux", "amd64"), fixtures.GoBinary(t, "windows", "amd64"))
	type h struct{ ssd, tl string }
	var mine []h
	for _, p := range files {
		b, _ := os.ReadFile(p)
		s, tl := Hash(b)
		mine = append(mine, h{s, tl})

		out, err := exec.Command(ssdeepBin, "-b", p).Output() //nolint:gosec // fixed test tool
		if err != nil {
			t.Fatal(err)
		}
		ref := strings.Split(strings.Split(strings.TrimSpace(string(out)), "\n")[1], ",")[0]
		if s != ref {
			t.Errorf("ssdeep differs for %s:\n mine %s\n ref  %s", filepath.Base(p), s, ref)
		}
		tref, err := exec.Command(py, "-c", "import tlsh,sys;print(tlsh.hash(open(sys.argv[1],'rb').read()))", p).Output() //nolint:gosec // fixed test tool
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(tref)); tl != got {
			t.Errorf("TLSH differs for %s:\n mine %s\n ref  %s", filepath.Base(p), tl, got)
		}
	}
	// Distances: compare every pair against the reference.
	for i := 0; i < len(mine); i++ {
		for j := i + 1; j < len(mine); j++ {
			if mine[i].tl == "" || mine[j].tl == "" {
				continue
			}
			out, err := exec.Command(py, "-c", "import tlsh,sys;print(tlsh.diff(sys.argv[1],sys.argv[2]))", mine[i].tl, mine[j].tl).Output() //nolint:gosec // fixed test tool
			if err != nil {
				t.Fatal(err)
			}
			want, _ := strconv.Atoi(strings.TrimSpace(string(out)))
			if got, ok := DiffTLSH(mine[i].tl, mine[j].tl); !ok || got != want {
				t.Errorf("TLSH distance %d/%d: mine %d, reference %d", i, j, got, want)
			}
		}
	}
	nonzero := 0
	// ssdeep scores against the reference matcher, pair by pair: `ssdeep -k a b`
	// prints "b:y matches a:x (score)" only when the score is above zero.
	for i := 0; i < len(mine); i++ {
		for j := i + 1; j < len(mine); j++ {
			a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
			hdr := "ssdeep,1.1--blocksize:hash:hash,filename\n"
			if err := os.WriteFile(a, []byte(hdr+mine[i].ssd+",\"x\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(b, []byte(hdr+mine[j].ssd+",\"y\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			ref, err := exec.Command(ssdeepBin, "-k", a, b).CombinedOutput() //nolint:gosec // fixed test tool
			if err != nil {
				t.Fatalf("reference ssdeep failed: %v: %s", err, ref)
			}
			want := 0
			if line := strings.TrimSpace(string(ref)); strings.Contains(line, "matches") {
				open, end := strings.LastIndex(line, "("), strings.LastIndex(line, ")")
				if open < 0 || end < open {
					t.Fatalf("unparseable reference output %q", line)
				}
				want, _ = strconv.Atoi(line[open+1 : end])
			}
			got, _ := CompareSSDeep(mine[i].ssd, mine[j].ssd)
			if got > 0 {
				nonzero++
			}
			if got != want {
				t.Errorf("ssdeep score %d/%d: mine %d, reference %d", i, j, got, want)
			}
		}
	}
	if nonzero == 0 {
		t.Error("no non-zero ssdeep score was cross-checked; the test data no longer exercises the matcher")
	}
}

func init() { _ = strconv.Itoa }

func TestSketchEstimatesOverlap(t *testing.T) {
	mk := func(from, to int) []uint32 {
		return Sketch(func(y func(string)) {
			for i := from; i < to; i++ {
				y("string-number-" + strconv.Itoa(i))
			}
		})
	}
	a, same, half, disjoint := mk(0, 1000), mk(0, 1000), mk(500, 1500), mk(5000, 6000)
	if j, ok := SketchJaccard(a, same); !ok || j != 1 {
		t.Fatalf("identical sets: %v %v", j, ok)
	}
	// True Jaccard of [0,1000) and [500,1500) is 500/1500 = 0.333.
	if j, _ := SketchJaccard(a, half); j < 0.2 || j > 0.47 {
		t.Fatalf("half overlap estimated as %.3f (true 0.333, expected error about 0.09)", j)
	}
	if j, _ := SketchJaccard(a, disjoint); j > 0.1 {
		t.Fatalf("disjoint sets estimated as %.3f", j)
	}
	if Sketch(func(func(string)) {}) != nil {
		t.Fatal("an empty set must have no sketch, not a sketch that looks like a match")
	}
	if _, ok := SketchJaccard(a, nil); ok {
		t.Fatal("a missing sketch must not be comparable")
	}
}

func report(imports []string, secs []string, sketch []uint32, imphash string, inds, caps []string) *models.Report {
	b := &models.Binary{ImportHash: imphash}
	im := models.Import{Library: "K.dll"}
	for _, f := range imports {
		im.Functions = append(im.Functions, models.ImportFn{Name: f})
	}
	b.Imports = []models.Import{im}
	for _, s := range secs {
		b.Sections = append(b.Sections, models.Section{Name: s, Perms: "r-x", RawSize: 8192})
	}
	a := &models.Analysis{Fuzzy: models.Fuzzy{StringSketch: sketch}}
	for _, i := range inds {
		a.Indicators = append(a.Indicators, models.Indicator{Type: "domain", Value: i})
	}
	for _, c := range caps {
		a.Capabilities = append(a.Capabilities, models.Capability{ID: c})
	}
	return &models.Report{Binary: b, Analysis: a}
}

func many(prefix string, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		out = append(out, prefix+strconv.Itoa(i))
	}
	return out
}

func TestStructuralOverlap(t *testing.T) {
	sk := Sketch(func(y func(string)) {
		for _, s := range many("s", 300) {
			y(s + "-padding")
		}
	})
	a := report(many("api", 20), []string{".text", ".data", ".rsrc"}, sk, "h1", []string{"x.example.com"}, []string{"c1", "c2"})
	same := Structural(a, a)
	if !same.HasOverlap || same.Overlap != 1 || len(same.Components) != 6 {
		t.Fatalf("a file against itself must be exactly 1: %+v", same)
	}
	b := report(many("zzz", 20), []string{".a", ".b", ".c"}, Sketch(func(y func(string)) { y("completely-different-string") }), "h2", []string{"y.example.org"}, []string{"c9"})
	diff := Structural(a, b)
	if !diff.HasOverlap || diff.Overlap > 0.1 {
		t.Fatalf("unrelated reports: %+v", diff)
	}
}

func TestComponentsWithoutDataAreOmittedNotZero(t *testing.T) {
	a := report(many("api", 20), []string{".text", ".data", ".rsrc"}, nil, "", nil, nil)
	b := report(many("api", 20), []string{".text", ".data", ".rsrc"}, nil, "", nil, nil)
	s := Structural(a, b)
	names := map[string]bool{}
	for _, c := range s.Components {
		names[c.Name] = true
	}
	if names["strings"] || names["indicators"] || names["capabilities"] || names["import hash"] {
		t.Fatalf("components without data on either side must be omitted: %+v", s.Components)
	}
	if s.HasOverlap {
		t.Fatalf("two comparable components are not enough for a combined number: %+v", s)
	}
	// Too few imports: not comparable either.
	tiny := report(many("api", 2), nil, nil, "", nil, nil)
	if s := Structural(tiny, tiny); len(s.Components) != 0 {
		t.Fatalf("%+v", s.Components)
	}
	if s := Structural(&models.Report{}, &models.Report{}); len(s.Components) != 0 || s.HasOverlap {
		t.Fatalf("%+v", s)
	}
}

func TestWeightsAreFixedAndSumToOne(t *testing.T) {
	var sum float64
	for _, w := range weights {
		sum += w
	}
	if sum < 0.999 || sum > 1.001 {
		t.Fatalf("weights sum to %v", sum)
	}
}

func FuzzParsers(f *testing.F) {
	f.Add("T1" + strings.Repeat("A", 70))
	f.Add("3:abc:def")
	f.Fuzz(func(t *testing.T, s string) {
		DiffTLSH(s, s)
		CompareSSDeep(s, s)
	})
}

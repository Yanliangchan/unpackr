// Package similarity measures how alike two files are. It deliberately does
// not invent a new fuzzy hash: it uses the established ssdeep and TLSH
// algorithms (validated byte-for-byte against their reference implementations
// in this repository's tests) and adds a documented structural overlap.
// See docs/SIMILARITY.md for the algorithm, weights and caveats.
package similarity

import (
	"encoding/hex"
	"hash/fnv"
	"math"
	"strings"

	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MinTLSHBytes is the smallest input TLSH can hash.
const MinTLSHBytes = 50

// SketchSize is the number of MinHash slots. The estimate of a Jaccard index
// has a standard error of about 1/sqrt(SketchSize), roughly 0.09.
const SketchSize = 128

// Hash computes ssdeep and TLSH for data. Either is empty when the input is
// too small or too uniform for the algorithm.
func Hash(data []byte) (ssd, tl string) {
	if len(data) >= 1 {
		if s, err := ssdeep.FuzzyBytes(data); err == nil {
			ssd = s
		}
	}
	if len(data) >= MinTLSHBytes {
		if h, err := tlsh.HashBytes(data); err == nil && h != nil {
			if s := h.String(); len(s) == 70 {
				// The reference implementation prints "T1" and upper case.
				tl = "T1" + strings.ToUpper(s)
			}
		}
	}
	return
}

// CompareSSDeep returns the ssdeep match score 0-100. ok is false when either
// hash is missing or malformed, or the block sizes are incomparable.
func CompareSSDeep(a, b string) (score int, ok bool) {
	if a == "" || b == "" {
		return 0, false
	}
	s, err := ssdeep.Distance(a, b)
	if err != nil {
		return 0, false
	}
	return s, true
}

// DiffTLSH returns the TLSH distance (0 means identical; larger is less
// alike). ok is false when either hash is missing or malformed.
func DiffTLSH(a, b string) (dist int, ok bool) {
	ta, tb := parseTLSH(a), parseTLSH(b)
	if ta == nil || tb == nil {
		return 0, false
	}
	return ta.Diff(tb), true
}

func parseTLSH(s string) *tlsh.TLSH {
	s = strings.TrimPrefix(strings.TrimSpace(s), "T1")
	if len(s) != 70 { // the library indexes the decoded bytes without checking
		return nil
	}
	if _, err := hex.DecodeString(s); err != nil {
		return nil
	}
	t, err := tlsh.ParseStringToTlsh(strings.ToLower(s))
	if err != nil {
		return nil
	}
	return t
}

// TLSHLabel gives the conventional reading of a TLSH distance. The bands are
// the commonly quoted ones for TLSH, not calibrated on this tool's data, and
// they say nothing about malware families.
func TLSHLabel(d int) string {
	switch {
	case d == 0:
		return "identical hashes"
	case d <= 30:
		return "very close"
	case d <= 100:
		return "related"
	case d <= 200:
		return "distant"
	}
	return "unrelated"
}

// SSDeepLabel gives the conventional reading of an ssdeep score.
func SSDeepLabel(s int) string {
	switch {
	case s >= 90:
		return "very close"
	case s >= 50:
		return "related"
	case s > 0:
		return "weakly related"
	}
	return "no match"
}

// Sketch builds a MinHash sketch of a set of strings, so the similarity of two
// large string sets can be estimated from SketchSize numbers each.
func Sketch(items func(yield func(string))) []uint32 {
	sk := make([]uint32, SketchSize)
	for i := range sk {
		sk[i] = math.MaxUint32
	}
	any := false
	items(func(s string) {
		any = true
		h := fnv.New64a()
		_, _ = h.Write([]byte(s))
		base := h.Sum64()
		// Slot i uses the 64-bit hash mixed with i (splitmix-style), which
		// gives independent-looking permutations without SketchSize hashes.
		for i := range sk {
			x := base + uint64(i+1)*0x9e3779b97f4a7c15
			x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
			x = (x ^ (x >> 27)) * 0x94d049bb133111eb
			x ^= x >> 31
			if v := uint32(x >> 32); v < sk[i] {
				sk[i] = v
			}
		}
	})
	if !any {
		return nil
	}
	return sk
}

// SketchJaccard estimates the Jaccard index of two sketched sets.
func SketchJaccard(a, b []uint32) (float64, bool) {
	if len(a) != SketchSize || len(b) != SketchSize {
		return 0, false
	}
	eq := 0
	for i := range a {
		if a[i] == b[i] {
			eq++
		}
	}
	return float64(eq) / SketchSize, true
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	inter := 0
	for k := range a {
		if b[k] {
			inter++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}

func set(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// Component weights. They are fixed, published and not calibrated: they
// express that import and string overlap are stronger signals than a shared
// section list, and nothing more. See docs/SIMILARITY.md.
var weights = map[string]float64{
	"imports": 0.30, "strings": 0.20, "sections": 0.15, "indicators": 0.15, "capabilities": 0.10, "import hash": 0.10,
}

// MinComponents is how many comparable components are required before a
// combined overlap is shown at all.
const MinComponents = 3

func importSet(b *models.Binary) []string {
	var out []string
	for _, im := range b.Imports {
		for _, f := range im.Functions {
			n := f.Name
			if f.ByOrdinal {
				n = "#" + itoa(int(f.Ordinal))
			}
			out = append(out, strings.ToLower(im.Library)+"!"+n)
		}
	}
	return out
}

func sectionSet(b *models.Binary) []string {
	var out []string
	for _, s := range b.Sections {
		out = append(out, s.Name+":"+s.Perms+":"+itoa(int(s.RawSize/4096)))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Structural compares two reports component by component. Components that
// cannot be compared (too little data on either side) are omitted rather than
// counted as zero.
func Structural(a, b *models.Report) models.Similarity {
	var comps []models.SimilarityComponent
	add := func(name string, score float64, note string) {
		comps = append(comps, models.SimilarityComponent{Name: name, Score: math.Round(score*1000) / 1000, Weight: weights[name], Note: note})
	}
	if a.Binary != nil && b.Binary != nil {
		ia, ib := importSet(a.Binary), importSet(b.Binary)
		if len(ia) >= 5 && len(ib) >= 5 {
			add("imports", jaccard(set(ia), set(ib)), "Jaccard over library!function pairs")
		}
		sa, sb := sectionSet(a.Binary), sectionSet(b.Binary)
		if len(sa) >= 3 && len(sb) >= 3 {
			add("sections", jaccard(set(sa), set(sb)), "Jaccard over name, permissions and size (4 KiB steps)")
		}
		if a.Binary.ImportHash != "" && b.Binary.ImportHash != "" {
			v := 0.0
			if a.Binary.ImportHash == b.Binary.ImportHash {
				v = 1
			}
			add("import hash", v, "equality of the pefile-compatible import hash")
		}
	}
	if a.Analysis != nil && b.Analysis != nil {
		if j, ok := SketchJaccard(a.Analysis.Fuzzy.StringSketch, b.Analysis.Fuzzy.StringSketch); ok {
			add("strings", j, "MinHash estimate (128 slots, error about 0.09) over all strings of 8+ characters")
		}
		var ia, ib []string
		for _, i := range a.Analysis.Indicators {
			ia = append(ia, i.Type+":"+i.Value)
		}
		for _, i := range b.Analysis.Indicators {
			ib = append(ib, i.Type+":"+i.Value)
		}
		if len(ia) > 0 && len(ib) > 0 {
			add("indicators", jaccard(set(ia), set(ib)), "Jaccard over indicator type and value")
		}
		var ca, cb []string
		for _, c := range a.Analysis.Capabilities {
			ca = append(ca, c.ID)
		}
		for _, c := range b.Analysis.Capabilities {
			cb = append(cb, c.ID)
		}
		if len(ca) > 0 && len(cb) > 0 {
			add("capabilities", jaccard(set(ca), set(cb)), "Jaccard over inferred capability ids")
		}
	}
	out := models.Similarity{Components: comps}
	if len(comps) >= MinComponents {
		var num, den float64
		for _, c := range comps {
			num += c.Score * c.Weight
			den += c.Weight
		}
		out.Overlap = math.Round(num/den*1000) / 1000
		out.HasOverlap = true
	}
	if a.Analysis != nil && b.Analysis != nil {
		fa, fb := a.Analysis.Fuzzy, b.Analysis.Fuzzy
		if d, ok := DiffTLSH(fa.TLSH, fb.TLSH); ok {
			out.TLSHDistance, out.HasTLSH = d, true
		}
		if s, ok := CompareSSDeep(fa.SSDeep, fb.SSDeep); ok {
			out.SSDeepScore, out.HasSSDeep = s, true
		}
	}
	return out
}

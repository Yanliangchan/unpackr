// Package capabilities infers what an executable could do from what it
// references: imported APIs, API names stored as strings, command-line
// fragments and cryptographic constants.
//
// Wording is a hard rule. A capability always reads "references X, consistent
// with Y". An imported API proves that the file asks the loader for it, not
// that the code runs, reaches it, or succeeds. Nothing here is "observed
// behaviour" because samples are never executed.
package capabilities

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/analysis"
	"github.com/Yanliangchan/unpackr/internal/confidence"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Evidence kinds reported on a capability.
const (
	KindImported         = "imported"
	KindStringReferenced = "string-referenced"
	KindStructural       = "structural"
)

// forms returns the lowercase spellings under which an API may be listed:
// the exact name, the name without a trailing A/W character-set suffix, the
// name without a leading underscore (Mach-O), and Nt for Zw.
func forms(name string) []string {
	out := []string{strings.ToLower(name)}
	n := name
	if len(n) > 4 && (strings.HasSuffix(n, "A") || strings.HasSuffix(n, "W")) {
		prev := n[len(n)-2]
		if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') {
			out = append(out, strings.ToLower(n[:len(n)-1]))
		}
	}
	for _, f := range append([]string(nil), out...) {
		if strings.HasPrefix(f, "_") && len(f) > 1 {
			out = append(out, f[1:])
		}
		if strings.HasPrefix(f, "zw") {
			out = append(out, "nt"+f[2:])
		}
	}
	return out
}

type index struct {
	imported map[string]string // form -> original import name
	strs     map[string]string // form -> original string (exact API name stored as text)
	hits     []lowered
}

type lowered struct {
	lower  string
	offset int64
	text   string
	enc    string
}

func buildIndex(in *analysis.Input) *index {
	ix := &index{imported: map[string]string{}, strs: map[string]string{}}
	if in.Bin != nil {
		bins := []*models.Binary{in.Bin}
		for i := range in.Bin.Slices {
			bins = append(bins, &in.Bin.Slices[i])
		}
		for _, b := range bins {
			for _, im := range b.Imports {
				for _, f := range im.Functions {
					if f.Name == "" {
						continue
					}
					for _, k := range forms(f.Name) {
						if _, ok := ix.imported[k]; !ok {
							ix.imported[k] = f.Name
						}
					}
				}
			}
		}
	}
	if in.Scan != nil {
		for _, h := range in.Scan.Hits {
			if len(h.Text) > 400 {
				continue
			}
			ix.hits = append(ix.hits, lowered{strings.ToLower(h.Text), h.Offset, h.Text, h.Enc})
			if len(h.Text) <= 64 && !strings.ContainsAny(h.Text, " \t") {
				for _, k := range forms(h.Text) {
					if _, ok := ix.strs[k]; !ok {
						ix.strs[k] = h.Text
					}
				}
			}
		}
	}
	return ix
}

// Detect evaluates every applicable rule. packed lowers confidence in
// import-based results, because the import table of a packed file describes
// the packer's stub.
func Detect(in *analysis.Input, packedState string) []models.Capability {
	family := in.Family
	if family == "" && in.Bin != nil {
		family = in.Bin.Family()
	}
	ix := buildIndex(in)
	var out []models.Capability
	for _, r := range RulesFor(family) {
		if c, ok := evaluate(r, in, ix, packedState); ok {
			out = append(out, c)
		}
	}
	if c, ok := correlateExfiltration(out); ok {
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].ID < out[j].ID
	})
	if out == nil {
		out = []models.Capability{}
	}
	return out
}

func evaluate(r Rule, in *analysis.Input, ix *index, packedState string) (models.Capability, bool) {
	need := r.Need
	if need == 0 {
		need = len(r.Groups)
	}
	var chain []models.ChainStep
	var sigs []models.Signal
	kinds := map[string]bool{}
	importedGroups, stringGroups := 0, 0
	var importedNames []string

	for _, grp := range r.Groups {
		var imp, str []string
		seenI, seenS := map[string]bool{}, map[string]bool{}
		for _, api := range grp.APIs {
			for _, k := range forms(api) {
				if name, ok := ix.imported[k]; ok && !seenI[name] {
					seenI[name] = true
					imp = append(imp, name)
				}
				if name, ok := ix.strs[k]; ok && !seenS[name] {
					seenS[name] = true
					str = append(str, name)
				}
			}
		}
		switch {
		case len(imp) > 0:
			importedGroups++
			chain = append(chain, models.ChainStep{Label: grp.Label, APIs: dedupe(imp), Source: KindImported})
			importedNames = append(importedNames, imp...)
			kinds[KindImported] = true
		case len(str) > 0:
			stringGroups++
			chain = append(chain, models.ChainStep{Label: grp.Label, APIs: dedupe(str), Source: KindStringReferenced})
			kinds[KindStringReferenced] = true
		}
	}
	satisfied := importedGroups + stringGroups
	haveGroups := len(r.Groups) > 0 && satisfied >= need

	if haveGroups {
		if importedGroups > 0 {
			strength := r.Partial
			if importedGroups == len(r.Groups) {
				strength = r.Complete
			}
			if strength == "" {
				strength = "weak"
			}
			ev := in.Sink.Add("import", strings.Join(dedupe(importedNames), ", "), -1, 0, "", "capability/"+r.ID+"/imports", "imports:"+r.ID)
			sigs = append(sigs, models.Signal{ID: "cap." + r.ID + ".imports", Detail: fmt.Sprintf("%d of %d API groups imported", importedGroups, len(r.Groups)), Strength: strength, Family: "imports:" + r.ID, Evidence: []string{ev}})
		}
		if stringGroups > 0 {
			strength := "weak"
			if satisfied == len(r.Groups) {
				strength = "moderate"
			}
			var names []string
			for _, c := range chain {
				if c.Source == KindStringReferenced {
					names = append(names, c.APIs...)
				}
			}
			ev := in.Sink.Add("string", strings.Join(dedupe(names), ", "), -1, 0, "", "capability/"+r.ID+"/strings", "strings:"+r.ID)
			sigs = append(sigs, models.Signal{ID: "cap." + r.ID + ".name-strings", Detail: fmt.Sprintf("%d API group(s) named as strings (typical of run-time resolution)", stringGroups), Strength: strength, Family: "strings:" + r.ID, Evidence: []string{ev}})
		}
	}

	var patternHits []string
	for _, p := range r.Strings {
		needle := strings.ToLower(p.Substr)
		for _, h := range ix.hits {
			if strings.Contains(h.lower, needle) {
				ev := in.Sink.Add("string", h.text, h.offset, int64(len(h.text)), in.SectionAt(h.offset), "capability/"+r.ID+"/string", "text:"+r.ID+":"+p.Label)
				sigs = append(sigs, models.Signal{ID: "cap." + r.ID + ".string", Detail: "contains " + p.Label, Strength: p.Strength, Family: "text:" + r.ID + ":" + p.Label, Evidence: []string{ev}})
				patternHits = append(patternHits, p.Label)
				kinds[KindStringReferenced] = true
				break
			}
		}
	}
	for _, b := range r.Bytes {
		if off := bytes.Index(in.Data, b.Needle); off >= 0 {
			ev := in.Sink.Add("constant", b.Label, int64(off), int64(len(b.Needle)), in.SectionAt(int64(off)), "capability/"+r.ID+"/constant", "const:"+r.ID+":"+b.Label)
			sigs = append(sigs, models.Signal{ID: "cap." + r.ID + ".constant", Detail: b.Label + " present", Strength: b.Strength, Family: "const:" + r.ID + ":" + b.Label, Evidence: []string{ev}})
			patternHits = append(patternHits, b.Label)
			kinds[KindStructural] = true
		}
	}
	// Rules with groups need those groups: patterns alone may not stand in for
	// the import evidence unless the rule has no groups.
	if len(r.Groups) > 0 && !haveGroups && len(patternHits) == 0 {
		return models.Capability{}, false
	}
	if len(sigs) == 0 {
		return models.Capability{}, false
	}

	conf, why := confidence.Derive(sigs, 0)
	caveat := r.Benign
	if (packedState == models.PackConfirmed || packedState == models.PackLikely) && kinds[KindImported] {
		conf = confidence.Lower(conf, 1)
		why += "; lowered because the file appears packed and its import table may describe the packer stub"
		caveat = strings.TrimSpace(caveat + " The file appears packed, so these imports may not belong to the packed program.")
	}
	var ks []string
	for k := range kinds {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	c := models.Capability{
		ID: r.ID, Name: r.Name, Category: r.Category, Attack: r.Attack,
		Confidence: conf, Rationale: why, Severity: r.Severity,
		Chain: chain, EvidenceKinds: ks, Signals: sigs, Caveat: caveat,
	}
	c.Summary = describe(r, chain, patternHits)
	if c.Chain == nil {
		c.Chain = []models.ChainStep{}
	}
	return c, true
}

// describe builds the hedged summary sentence.
func describe(r Rule, chain []models.ChainStep, patterns []string) string {
	var parts []string
	for _, c := range chain {
		verb := "imports"
		if c.Source == KindStringReferenced {
			verb = "names as strings"
		}
		parts = append(parts, fmt.Sprintf("%s %s", verb, strings.Join(c.APIs, "/")))
	}
	if len(patterns) > 0 {
		parts = append(parts, "contains "+strings.Join(dedupe(patterns), ", "))
	}
	s := "The file " + strings.Join(parts, "; ") + ", consistent with " + r.Summary + "."
	return s + " This shows what the file references, not that the behaviour occurs."
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// correlateExfiltration notes the co-occurrence of a network capability with
// a collection or credential capability. It is deliberately speculative.
func correlateExfiltration(caps []models.Capability) (models.Capability, bool) {
	var net, src []models.Capability
	for _, c := range caps {
		switch {
		case strings.HasPrefix(c.ID, "network.client") || c.ID == "network.download":
			net = append(net, c)
		case c.Category == "credential access" || c.Category == "data collection":
			src = append(src, c)
		}
	}
	if len(net) == 0 || len(src) == 0 {
		return models.Capability{}, false
	}
	var steps []models.ChainStep
	steps = append(steps, models.ChainStep{Label: "can communicate", APIs: ids(net), Source: KindStructural})
	steps = append(steps, models.ChainStep{Label: "can gather data", APIs: ids(src), Source: KindStructural})
	sig := models.Signal{ID: "cap.exfil.cooccurrence", Detail: "network and collection capabilities both inferred", Strength: "weak", Family: "correlation"}
	conf, why := confidence.Derive([]models.Signal{sig}, 0)
	return models.Capability{
		ID: "exfil.possible", Name: "Potential data exfiltration", Category: "potential exfiltration", Attack: []string{"T1041"},
		Confidence: conf, Rationale: why + "; this is a co-occurrence of two other inferences, not a finding of its own",
		Severity: models.SeverityMedium, Chain: steps, EvidenceKinds: []string{KindStructural}, Signals: []models.Signal{sig},
		Summary: "The file shows both a network capability (" + strings.Join(ids(net), ", ") + ") and a data-gathering capability (" + strings.Join(ids(src), ", ") + "), consistent with software that could send collected data off the host. The two may be unrelated; this is a prompt to look at how they connect, not evidence that data leaves.",
		Caveat:  "Most programs with a network feature also read local data for ordinary reasons.",
	}, true
}

func ids(cs []models.Capability) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.ID)
	}
	sort.Strings(out)
	return out
}

package database

import (
	"sort"

	"github.com/Yanliangchan/unpackr/internal/similarity"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// SimilarHit is a stored sample that resembles another file.
type SimilarHit struct {
	SHA256, Name string
	Similarity   models.Similarity
	Shared       []string // pivot kinds shared (imphash, section-layout, host ...)
}

// maxStructural bounds how many candidates have their full report loaded.
const maxStructural = 200

// Similar ranks stored samples by resemblance to rep. Fuzzy hashes are
// compared with every stored sample (cheap, in memory); the structural
// overlap needs the stored report, so it is computed for the closest
// candidates and for samples sharing a pivot value.
func (d *DB) Similar(rep *models.Report, limit int) ([]SimilarHit, error) {
	self := rep.File.Hashes.SHA256
	type cand struct {
		sha         string
		dist, score int
		hasT, hasS  bool
		shared      []string
	}
	cands := map[string]*cand{}
	get := func(sha string) *cand {
		c := cands[sha]
		if c == nil {
			c = &cand{sha: sha}
			cands[sha] = c
		}
		return c
	}
	rows, err := d.sql.Query("SELECT sha256, kind, value FROM features WHERE kind IN ('tlsh','ssdeep') AND sha256 != ?", self)
	if err != nil {
		return nil, err
	}
	var myT, myS string
	if rep.Analysis != nil {
		myT, myS = rep.Analysis.Fuzzy.TLSH, rep.Analysis.Fuzzy.SSDeep
	}
	for rows.Next() {
		var sha, kind, val string
		if err := rows.Scan(&sha, &kind, &val); err != nil {
			_ = rows.Close()
			return nil, err
		}
		c := get(sha)
		switch kind {
		case "tlsh":
			if dist, ok := similarity.DiffTLSH(myT, val); ok {
				c.dist, c.hasT = dist, true
			}
		case "ssdeep":
			if sc, ok := similarity.CompareSSDeep(myS, val); ok && sc > 0 {
				c.score, c.hasS = sc, true
			}
		}
	}
	_ = rows.Close()

	// Samples sharing a pivot value are candidates whatever their hashes say.
	pivots := map[string]bool{"imphash": true, "section-layout": true, "host": true, "packer": false}
	for _, f := range Features(rep) {
		if !pivots[f[0]] {
			continue
		}
		pr, err := d.sql.Query("SELECT sha256 FROM features WHERE kind = ? AND value = ? AND sha256 != ? LIMIT 500", f[0], f[1], self)
		if err != nil {
			return nil, err
		}
		for pr.Next() {
			var sha string
			if err := pr.Scan(&sha); err != nil {
				_ = pr.Close()
				return nil, err
			}
			c := get(sha)
			c.shared = append(c.shared, f[0])
		}
		_ = pr.Close()
	}

	var list []*cand
	for _, c := range cands {
		if c.hasT || c.hasS || len(c.shared) > 0 {
			list = append(list, c)
		}
	}
	rank := func(c *cand) int { // lower is closer; no hash comparison sorts last
		if c.hasT {
			return c.dist
		}
		if c.hasS {
			return 400 - c.score
		}
		return 1000
	}
	sort.SliceStable(list, func(i, j int) bool {
		if ri, rj := rank(list[i]), rank(list[j]); ri != rj {
			return ri < rj
		}
		return len(list[i].shared) > len(list[j].shared)
	})
	if len(list) > maxStructural {
		list = list[:maxStructural]
	}

	var out []SimilarHit
	for _, c := range list {
		other, err := d.LoadReport(c.sha)
		if err != nil {
			continue // a damaged stored report only drops that candidate
		}
		sim := similarity.Structural(rep, other)
		sim.TLSHDistance, sim.HasTLSH = c.dist, c.hasT
		sim.SSDeepScore, sim.HasSSDeep = c.score, c.hasS
		out = append(out, SimilarHit{SHA256: c.sha, Name: other.File.Name, Similarity: sim, Shared: dedupeStrings(c.shared)})
	}
	sort.SliceStable(out, func(i, j int) bool { return closeness(out[i]) > closeness(out[j]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// closeness orders hits: the structural overlap when it exists, otherwise a
// value derived from the hash comparisons. It is used only for sorting.
func closeness(h SimilarHit) float64 {
	s := h.Similarity
	switch {
	case s.HasOverlap:
		return 1 + s.Overlap
	case s.HasTLSH:
		return 1 - float64(s.TLSHDistance)/1000
	case s.HasSSDeep:
		return float64(s.SSDeepScore) / 200
	}
	return 0
}

func dedupeStrings(in []string) []string {
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

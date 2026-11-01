package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/capabilities"
	"github.com/Yanliangchan/unpackr/internal/reverse"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// runReverse asks radare2 where the imported APIs behind the capabilities are
// referenced, and attaches the answer to the analysis. A missing or unusable
// engine is reported, never silent.
func runReverse(ctx context.Context, f *os.File, size int64, rep *models.Report, a *models.Analysis, o Options) {
	skip := func(why string) {
		a.Reverse = &models.Reverse{Engine: "radare2", Skipped: why, CallSites: []models.ReverseCall{}}
		rep.NotRun = append(rep.NotRun, "reverse-engineering: skipped: "+why)
	}
	family := ""
	if rep.Binary != nil {
		family = rep.Binary.Family()
	}
	if family != "elf" && family != "pe" {
		skip("call-site analysis is verified for ELF and PE files only")
		return
	}
	mem := uint64(o.Config.WorkerMemoryMB) << 20
	tool, err := reverse.Locate(ctx, mem)
	switch {
	case errors.Is(err, exec.ErrNotFound):
		skip("radare2 is not installed")
		return
	case errors.Is(err, worker.ErrExecSandbox):
		skip("radare2 could not be fully sandboxed (" + textutil.Sanitize(err.Error()) + ")")
		return
	case err != nil:
		skip(textutil.Sanitize(err.Error()))
		return
	}
	apis := reverseTargets(rep.Binary, a.Capabilities)
	timeout := time.Duration(o.Config.TimeoutSeconds) * time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	res, err := reverse.Run(ctx, tool, io.NewSectionReader(f, 0, size), family, apis, reverse.Options{Timeout: timeout, MemoryBytes: mem})
	if err != nil {
		skip("radare2 failed: " + textutil.Sanitize(err.Error()))
		return
	}
	if res.Skipped != "" {
		skip(res.Skipped)
		return
	}
	if len(apis) == 0 {
		res.Notes = append(res.Notes, "no imported API behind a reported capability, so no call sites were looked up")
	}
	// Evidence for each call site, then a plain-language note on the capabilities.
	for i := range res.CallSites {
		c := &res.CallSites[i]
		id := fmt.Sprintf("r%d", len(rep.Evidence)+1)
		va := c.At
		rep.Evidence = append(rep.Evidence, models.Evidence{
			ID: id, Kind: "call-site", Value: fmt.Sprintf("%s references %s", orNone(c.Function), c.API),
			Loc: models.Location{VA: &va}, Source: models.Source{Module: "reverse", Engine: "radare2", Version: tool.Version, Rule: "axtj"},
			Family: "reverse:callsite",
		})
		c.Evidence = id
	}
	annotateCapabilities(a, res)
	a.Reverse = res
	a.Engines = append(a.Engines, models.EngineStatus{Name: "radare2", Version: tool.Version, Status: "used"})
}

func orNone(s string) string {
	if s == "" {
		return "(no function)"
	}
	return s
}

// reverseTargets lists, most serious capability first, the imported APIs worth
// looking up, with the library each comes from (needed for PE).
func reverseTargets(b *models.Binary, caps []models.Capability) []reverse.API {
	if b == nil {
		return nil
	}
	lib := map[string]string{}
	for _, im := range b.Imports {
		for _, fn := range im.Functions {
			if fn.Name != "" {
				lib[strings.ToLower(fn.Name)] = im.Library
			}
		}
	}
	rank := map[models.Severity]int{models.SeverityHigh: 3, models.SeverityMedium: 2, models.SeverityLow: 1}
	sorted := append([]models.Capability(nil), caps...)
	sort.SliceStable(sorted, func(i, j int) bool { return rank[sorted[i].Severity] > rank[sorted[j].Severity] })
	seen := map[string]bool{}
	var out []reverse.API
	for _, c := range sorted {
		for _, step := range c.Chain {
			if step.Source != capabilities.KindImported {
				continue
			}
			for _, name := range step.APIs {
				k := strings.ToLower(name)
				if seen[k] || len(out) >= reverse.MaxAPIs {
					continue
				}
				l, ok := lib[k]
				if !ok {
					continue // not a name in the import table; nothing to look up
				}
				seen[k] = true
				api := reverse.API{Name: name}
				if b.Family() == "pe" {
					api.Library = l
				}
				out = append(out, api)
			}
		}
	}
	return out
}

// annotateCapabilities adds where the code uses a capability's APIs to the
// capability's caveat, which answers the question the import table cannot.
func annotateCapabilities(a *models.Analysis, rv *models.Reverse) {
	where := map[string][]string{}
	for _, c := range rv.CallSites {
		if c.Kind == "call" && c.Function != "" {
			where[strings.ToLower(c.API)] = append(where[strings.ToLower(c.API)], c.Function)
		}
	}
	for i := range a.Capabilities {
		c := &a.Capabilities[i]
		var notes []string
		for _, step := range c.Chain {
			for _, name := range step.APIs {
				if fns := dedupeStrings(where[strings.ToLower(name)]); len(fns) > 0 {
					notes = append(notes, fmt.Sprintf("%s is called from %s", name, strings.Join(fns, ", ")))
				}
			}
		}
		if len(notes) > 0 {
			if c.Caveat != "" {
				c.Caveat += " "
			}
			c.Caveat += "radare2: " + strings.Join(notes, "; ") + "."
		}
	}
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

package cli

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/Yanliangchan/unpackr/internal/engine"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// collectInputs expands files and directories. Directories are walked without
// following symlinks and only regular files are returned.
func collectInputs(paths []string, max int) ([]string, error) {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // unreadable entries are skipped, not fatal
			}
			if d.Type().IsRegular() {
				out = append(out, path)
				if len(out) > max {
					return fmt.Errorf("more than %d files; raise max_batch_files to scan more", max)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// analyzeAll runs Analyze over files with bounded concurrency.
func analyzeAll(ctx context.Context, files []string, o engine.Options, threads int) ([]*models.Report, map[string]error) {
	type result struct {
		rep *models.Report
		err error
	}
	results := make([]result, len(files))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for i, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, f string) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				results[i] = result{err: ctx.Err()}
				return
			}
			rep, err := engine.Analyze(ctx, f, o)
			results[i] = result{rep, err}
		}(i, f)
	}
	wg.Wait()
	var reps []*models.Report
	errs := map[string]error{}
	for i, r := range results {
		switch {
		case r.err != nil:
			errs[files[i]] = r.err
		case r.rep != nil:
			reps = append(reps, r.rep)
		}
	}
	return reps, errs
}

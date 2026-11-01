package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/extraction/pyinstaller"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// TaskExtractPyInstaller extracts a PyInstaller bundle inside a sandboxed
// worker whose only writable location is one private directory.
const TaskExtractPyInstaller = "extract-pyinstaller"

// SupportedContainers lists what extraction handles in this build.
var SupportedContainers = []string{"PyInstaller", OverlayArchiveName}

// ExtractParams configures the extraction worker.
type ExtractParams struct {
	OutDir string             `json:"out_dir"`
	Limits pyinstaller.Limits `json:"limits"`
}

func init() {
	worker.Register(TaskExtractPyInstaller, func(ctx context.Context, in io.ReaderAt, size int64, raw json.RawMessage) (any, error) {
		var p ExtractParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		return pyinstaller.Extract(in, size, p.OutDir, p.Limits)
	})
}

// runExtract pulls supported embedded content out of the sample. The worker
// can write only into a private directory; the parent re-verifies everything
// it produced (paths, types, sizes, hashes) before moving it into place.
func runExtract(ctx context.Context, f *os.File, size int64, rep *models.Report, o Options) {
	ex := &models.Extraction{Requested: true, Supported: SupportedContainers, Entries: []models.ExtractedEntry{}}
	rep.Extraction = ex
	cfg := o.Config

	work, err := unpacking.WorkDir()
	if err != nil {
		ex.Status, ex.Message = "failed", "could not create a private work directory: "+err.Error()
		return
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir
	out := filepath.Join(work, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		ex.Status, ex.Message = "failed", err.Error()
		return
	}
	lim := pyinstaller.DefaultLimits()
	lim.MaxTotalBytes = cfg.ExtractMaxMB << 20
	lim.MaxEntries = cfg.ExtractMaxEntries
	res, err := worker.Run(ctx, TaskExtractPyInstaller, ExtractParams{OutDir: out, Limits: lim}, f, size, worker.Options{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, MemoryLimitBytes: uint64(cfg.WorkerMemoryMB) << 20,
		WritableDirs: []string{out}, RequireSandbox: cfg.RequireSandbox,
	})
	if err != nil {
		ex.Status, ex.Message = "failed", textutil.Sanitize(err.Error())
		return
	}
	var got models.Extraction
	if err := json.Unmarshal(res.Raw, &got); err != nil {
		ex.Status, ex.Message = "failed", "undecodable worker result: "+err.Error()
		return
	}
	got.Requested, got.Supported = true, SupportedContainers
	if got.Entries == nil {
		got.Entries = []models.ExtractedEntry{}
	}
	*ex = got
	if ex.Status == "not-applicable" && runOverlay(ctx, f, size, rep, o, ex) {
		return
	}
	if ex.Status != "extracted" {
		return
	}
	if err := verifyExtraction(out, ex, cfg.ExtractMaxMB<<20, cfg.ExtractMaxEntries); err != nil {
		ex.Status, ex.Message = "rejected", "the extracted files failed verification: "+err.Error()
		ex.Entries = []models.ExtractedEntry{}
		return
	}
	dir := o.ArtifactDir
	if dir == "" {
		dir = "unpackr-out"
	}
	sha := rep.File.Hashes.SHA256
	final := filepath.Join(dir, "artifacts", "pyinstaller-"+sha[:16])
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		ex.Status, ex.Message = "failed", "could not create the artifact directory: "+err.Error()
		return
	}
	_ = os.RemoveAll(final) // same sample, same name: replace the previous extraction of it
	if err := moveDir(out, final); err != nil {
		ex.Status, ex.Message = "failed", "could not store the extracted files: "+err.Error()
		return
	}
	ex.Dir = final
	addExtractionFindings(rep, ex)
}

// verifyExtraction re-checks the worker's output from the parent's side.
func verifyExtraction(root string, ex *models.Extraction, maxBytes int64, maxEntries int) error {
	want := map[string]models.ExtractedEntry{}
	for _, e := range ex.Entries {
		if e.Path == "" {
			continue
		}
		clean := filepath.Clean(filepath.FromSlash(e.Path))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return fmt.Errorf("entry path %q leaves the output directory", e.Path)
		}
		want[clean] = e
	}
	if len(want) > maxEntries {
		return fmt.Errorf("%d files exceed the limit of %d", len(want), maxEntries)
	}
	var total int64
	seen := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link %s", p)
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		rel, _ := filepath.Rel(root, p)
		e, ok := want[rel]
		if !ok {
			return fmt.Errorf("unexpected file %s", rel)
		}
		st, err := d.Info()
		if err != nil {
			return err
		}
		if st.Size() != e.Size || st.Mode().Perm() != 0o600 {
			return fmt.Errorf("%s has size %d mode %o, expected %d / 600", rel, st.Size(), st.Mode().Perm(), e.Size)
		}
		b, err := os.ReadFile(p) //nolint:gosec // path built from a verified relative name under root
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != e.SHA256 {
			return fmt.Errorf("%s does not match its recorded hash", rel)
		}
		if total += st.Size(); total > maxBytes {
			return fmt.Errorf("extracted data exceeds %d bytes", maxBytes)
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(want) {
		return fmt.Errorf("%d files expected, %d found", len(want), seen)
	}
	return nil
}

// moveDir renames src to dst, or copies when they are on different devices.
func moveDir(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		in, err := os.Open(p) //nolint:gosec // under the verified work directory
		if err != nil {
			return err
		}
		defer in.Close() //nolint:errcheck // read-only
		return copyInto(target, in)
	})
}

func addExtractionFindings(rep *models.Report, ex *models.Extraction) {
	var scripts, bins []string
	for _, e := range ex.Entries {
		if e.Path == "" {
			continue
		}
		switch e.TypeName {
		case "script":
			scripts = append(scripts, e.Name)
		case "binary":
			if strings.HasPrefix(e.Format, "PE") || strings.HasPrefix(e.Format, "ELF") || strings.HasPrefix(e.Format, "Mach-O") {
				bins = append(bins, e.Name)
			}
		}
	}
	sum := fmt.Sprintf("%s. Entry scripts: %s. %d embedded native library/executable file(s).", ex.Message, strings.Join(scripts, ", "), len(bins))
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "extract.pyinstaller", Rule: "extract/pyinstaller", Class: models.ClassObservation, Category: "payload",
		Title:    "PyInstaller bundle extracted (Python " + ex.PythonVersion + ")",
		Summary:  sum,
		Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
		Rationale:  "the archive trailer, table of contents and every entry were read and bounds-checked; extracted files were re-verified by hash",
		EvidenceID: []string{},
		Action:     "Decompile the extracted .pyc entry scripts with a bytecode decompiler (for example pycdc or decompyle3) to read the program's logic. UNPACKR does not run extracted content.",
	})
}

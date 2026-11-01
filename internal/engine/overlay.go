package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/identification"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// OverlayArchiveName names the overlay archive support in SupportedContainers.
const OverlayArchiveName = "ZIP/RAR/7z/CAB overlay archive (needs 7-Zip)"

// overlaySearch is how far into the overlay the archive signature is looked
// for; self-extractor stubs put a small header in front of the archive.
const overlaySearch = 64 << 10

var archiveMagics = []struct {
	name  string
	magic []byte
}{
	{"ZIP", []byte("PK\x03\x04")},
	{"RAR", []byte("Rar!\x1a\x07")},
	{"7z", []byte("7z\xbc\xaf\x27\x1c")},
	{"CAB", []byte("MSCF\x00\x00\x00\x00")},
}

// findOverlayArchive returns where in the file an archive signature starts
// inside the overlay, and its kind.
func findOverlayArchive(r io.ReaderAt, ov *models.Region) (int64, string) {
	n := ov.Size
	if n > overlaySearch {
		n = overlaySearch
	}
	if n < 16 {
		return 0, ""
	}
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, ov.Offset); err != nil && !errors.Is(err, io.EOF) {
		return 0, ""
	}
	best, kind := -1, ""
	for _, m := range archiveMagics {
		if i := bytes.Index(buf, m.magic); i >= 0 && (best < 0 || i < best) {
			best, kind = i, m.name
		}
	}
	if best < 0 {
		return 0, ""
	}
	return ov.Offset + int64(best), kind
}

var reSevenZipVersion = regexp.MustCompile(`7-Zip(?: \(\w+\))?(?: \[\d+\])? (\d+\.\d+)`)

// locateSevenZip finds a native 7-Zip. Debian's /usr/bin/7z is a shell
// wrapper, which cannot run inside the sandbox, so wrappers are skipped in
// favour of the real executable.
func locateSevenZip() (*unpacking.Tool, error) {
	for _, name := range []string{"7zz", "7z", "7za", "7zr"} {
		if p, err := exec.LookPath(name); err == nil && isNative(p) {
			return unpacking.Locate(name)
		}
	}
	for _, p := range []string{"/usr/lib/7zip/7z", "/usr/libexec/7zip/7z", "/usr/lib/p7zip/7z"} {
		if isNative(p) {
			return unpacking.Locate(p)
		}
	}
	return nil, exec.ErrNotFound
}

func isNative(p string) bool {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return false
	}
	f, err := os.Open(real) //nolint:gosec // resolved tool path
	if err != nil {
		return false
	}
	defer f.Close() //nolint:errcheck // read-only
	var hdr [4]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return string(hdr[:]) == "\x7fELF" || string(hdr[:2]) == "MZ" || binaryMagicMachO(hdr[:])
}

func binaryMagicMachO(b []byte) bool {
	return len(b) >= 4 && (b[0] == 0xcf || b[0] == 0xce || b[0] == 0xca) && (b[1] == 0xfa || b[1] == 0xfe)
}

// runOverlay extracts an archive appended to an executable (a dropper's
// payload or a self-extractor's data) with 7-Zip. The tool runs in the exec
// sandbox on a copy of just the archive bytes with one writable directory; the
// parent then rejects anything that is not a plain regular file, re-hashes
// every file and enforces the size and entry limits itself. Nothing is run.
// It reports whether an archive was found.
func runOverlay(ctx context.Context, f *os.File, size int64, rep *models.Report, o Options, ex *models.Extraction) bool {
	if rep.Binary == nil || rep.Binary.Overlay == nil {
		return false
	}
	start, kind := findOverlayArchive(f, rep.Binary.Overlay)
	if kind == "" {
		return false
	}
	end := rep.Binary.Overlay.Offset + rep.Binary.Overlay.Size
	if end > size {
		end = size
	}
	*ex = models.Extraction{Requested: true, Supported: SupportedContainers, Kind: "overlay-archive", ArchiveFormat: kind,
		ArchiveOffset: start, ArchiveLength: end - start, Entries: []models.ExtractedEntry{}}
	fail := func(status, msg string) bool {
		ex.Status, ex.Message = status, msg
		return true
	}
	cfg := o.Config

	tool, err := locateSevenZip()
	if err != nil {
		return fail("failed", fmt.Sprintf("a %s archive follows the executable at offset %d, but 7-Zip is not installed. Install it (Debian/Kali: sudo apt install 7zip) and run with -x again; nothing else about the analysis is affected", kind, start))
	}
	work, err := unpacking.WorkDir()
	if err != nil {
		return fail("failed", "could not create a private work directory: "+err.Error())
	}
	defer os.RemoveAll(work) //nolint:errcheck // private temp dir

	mem := uint64(cfg.WorkerMemoryMB) << 20
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	probe, err := worker.RunExec(ctx, tool.Spec(work, nil, mem, 1<<20), 20*time.Second)
	if err != nil {
		if errors.Is(err, worker.ErrExecSandbox) {
			return fail("failed", "7-Zip was not run because it could not be fully sandboxed on this system ("+textutil.Sanitize(err.Error())+"); external tools never run unconfined")
		}
		return fail("failed", "7-Zip could not be started: "+textutil.Sanitize(err.Error()))
	}
	if m := reSevenZipVersion.FindStringSubmatch(probe.Stdout + probe.Stderr); m != nil {
		tool.Version = m[1]
	}

	in := filepath.Join(work, "in.bin")
	if err := copyInto(in, io.NewSectionReader(f, start, end-start)); err != nil {
		return fail("failed", "could not stage a copy of the archive: "+err.Error())
	}
	out := filepath.Join(work, "out")
	if err := os.Mkdir(out, 0o700); err != nil {
		return fail("failed", err.Error())
	}
	maxBytes := cfg.ExtractMaxMB << 20

	// List first: refuse bombs and over-large archives before writing anything.
	list, err := worker.RunExec(ctx, tool.Spec(work, []string{"l", "-slt", "-bd", "-p-", in}, mem, 1<<20), timeout)
	if err != nil {
		return fail("failed", "7-Zip listing failed: "+textutil.Sanitize(err.Error()))
	}
	if list.ExitCode != 0 {
		return fail("failed", overlayFailure(kind, list.Stdout+list.Stderr))
	}
	lst := parseListing(list.Stdout)
	files, total, encrypted := len(lst.Files), lst.Total, lst.Encrypted
	if encrypted {
		return fail("failed", fmt.Sprintf("the %s archive at offset %d is password protected. UNPACKR does not guess passwords; if you know it, extract it yourself with 7-Zip in an isolated environment", kind, start))
	}
	if files == 0 {
		return fail("not-applicable", fmt.Sprintf("a %s signature at offset %d did not open as an archive", kind, start))
	}
	if files > cfg.ExtractMaxEntries || total > maxBytes {
		return fail("rejected", fmt.Sprintf("the %s archive lists %d file(s) and %d bytes; the limits are %d files and %d bytes (extract_max_entries, extract_max_mb)", kind, files, total, cfg.ExtractMaxEntries, maxBytes))
	}

	run, err := worker.RunExec(ctx, tool.Spec(work, []string{"x", "-y", "-bd", "-aos", "-mmt1", "-p-", "-o" + out, in}, mem, uint64(maxBytes)), timeout)
	if err != nil {
		return fail("failed", "7-Zip extraction failed: "+textutil.Sanitize(err.Error()))
	}
	if run.ExitCode != 0 && run.ExitCode != 1 && run.ExitCode != 2 { // 1 warning, 2 some entries failed
		return fail("failed", overlayFailure(kind, run.Stdout+run.Stderr))
	}
	var skipped []models.ExtractedEntry
	if run.ExitCode != 0 {
		skipped = dropIncomplete(out, lst.Files)
		ex.Notes = append(ex.Notes, errorLines(run.Stdout+run.Stderr)...)
	}
	entries, err := collectOverlay(out, maxBytes, cfg.ExtractMaxEntries)
	if err != nil {
		ex.Entries = []models.ExtractedEntry{}
		return fail("rejected", "the extracted files failed verification: "+textutil.Sanitize(err.Error()))
	}
	if len(entries) == 0 {
		return fail("failed", fmt.Sprintf("7-Zip opened the %s archive but produced no files%s", kind, noteSuffix(ex.Notes)))
	}
	var sum int64
	for _, e := range entries {
		sum += e.Size
	}
	if err := verifyExtraction(out, &models.Extraction{Entries: entries}, maxBytes, cfg.ExtractMaxEntries); err != nil {
		return fail("rejected", "the extracted files failed verification: "+err.Error())
	}

	dir := o.ArtifactDir
	if dir == "" {
		dir = "unpackr-out"
	}
	final := filepath.Join(dir, "artifacts", "overlay-"+rep.File.Hashes.SHA256[:16])
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return fail("failed", "could not create the artifact directory: "+err.Error())
	}
	_ = os.RemoveAll(final) // same sample, same name: replace the previous extraction of it
	if err := moveDir(out, final); err != nil {
		return fail("failed", "could not store the extracted files: "+err.Error())
	}
	ex.Status, ex.Entries, ex.TotalBytes, ex.Dir = "extracted", append(entries, skipped...), sum, final
	ex.Message = fmt.Sprintf("7-Zip %s extracted %d file(s), %d bytes, from the %s archive at offset %d", tool.Version, len(entries), sum, kind, start)
	if len(skipped) > 0 {
		ex.Message += fmt.Sprintf("; %d listed file(s) could not be extracted (see notes)", len(skipped))
	}
	if lst.Comment != "" {
		ex.Notes = append(ex.Notes, "archive comment (a self-extractor's command script lives here): "+textutil.Sanitize(lst.Comment))
	}
	addOverlayFindings(rep, ex)
	return true
}

type listedFile struct {
	Path string
	Size int64
}

type listing struct {
	Files     []listedFile
	Total     int64
	Encrypted bool
	Comment   string
}

// maxComment bounds the archive comment kept in a report.
const maxComment = 2000

// parseListing reads `7z l -slt` output: an archive header, a "----------"
// line, then blocks of "Key = Value" lines separated by blank lines. It
// lists files (not directories), sums sizes and keeps the archive comment.
func parseListing(s string) listing {
	var l listing
	head, body, found := strings.Cut(s, "\n----------\n")
	if !found {
		head, body = "", s
	}
	if _, c, ok := strings.Cut(head, "\nComment = "); ok {
		c = strings.TrimSpace(c)
		if len(c) > maxComment {
			c = c[:maxComment]
		}
		l.Comment = c
	}
	var cur listedFile
	var isDir, enc, have bool
	flush := func() {
		if have && !isDir && cur.Path != "" {
			l.Files = append(l.Files, cur)
			l.Total += cur.Size
		}
		if have && enc {
			l.Encrypted = true
		}
		cur, isDir, enc, have = listedFile{}, false, false, false
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		have = true
		switch k {
		case "Path":
			cur.Path = v
		case "Size":
			fmt.Sscanf(v, "%d", &cur.Size) //nolint:errcheck // a bad size counts as 0 and is caught by the byte limit after extraction
		case "Folder":
			isDir = v == "+"
		case "Encrypted":
			enc = v == "+"
		}
	}
	flush()
	return l
}

// dropIncomplete removes files that 7-Zip listed but did not extract in full
// (missing, or a different size than listed), and returns them as skipped
// entries so the report says what is not there instead of showing empty files.
func dropIncomplete(root string, listed []listedFile) []models.ExtractedEntry {
	var out []models.ExtractedEntry
	for _, lf := range listed {
		rel := strings.TrimLeft(filepath.ToSlash(strings.ReplaceAll(lf.Path, "\\", "/")), "/")
		clean := filepath.Clean(filepath.FromSlash(rel))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			continue // 7-Zip renames these; the collected files still describe what is on disk
		}
		p := filepath.Join(root, clean)
		st, err := os.Lstat(p)
		if err == nil && st.Mode().IsRegular() && st.Size() == lf.Size {
			continue
		}
		if err == nil && st.Mode().IsRegular() {
			_ = os.Remove(p)
		}
		out = append(out, models.ExtractedEntry{Name: textutil.Sanitize(lf.Path), Type: "f", TypeName: "file", Size: lf.Size,
			Skipped: "7-Zip did not extract it completely"})
	}
	return out
}

// errorLines picks the "ERROR:" lines out of 7-Zip output.
func errorLines(out string) []string {
	var r []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ERROR:") && len(r) < 10 {
			msg := "7-Zip " + textutil.Sanitize(line)
			if strings.Contains(line, "Unsupported Method") {
				msg += " (some builds of 7-Zip cannot decompress RAR; try one that can, or extract by hand in an isolated environment)"
			}
			r = append(r, msg)
		}
	}
	return r
}

func noteSuffix(notes []string) string {
	if len(notes) == 0 {
		return ""
	}
	return ": " + notes[0]
}

func overlayFailure(kind, out string) string {
	out = textutil.Sanitize(out)
	if len(out) > 300 {
		out = out[:300]
	}
	return fmt.Sprintf("7-Zip could not read the %s archive (it may be damaged, truncated or not really an archive): %s", kind, strings.TrimSpace(out))
}

// collectOverlay walks what the sandboxed tool wrote. Anything that is not a
// plain file or directory is rejected, permissions are normalised to
// owner-only without execute, and every file is hashed here in the parent.
func collectOverlay(root string, maxBytes int64, maxEntries int) ([]models.ExtractedEntry, error) {
	var out []models.ExtractedEntry
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("symbolic link %s", textutil.Sanitize(p))
		}
		if d.IsDir() {
			return os.Chmod(p, 0o700)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", textutil.Sanitize(p))
		}
		if len(out) >= maxEntries {
			return fmt.Errorf("more than %d files", maxEntries)
		}
		if err := os.Chmod(p, 0o600); err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		fh, err := os.Open(p) //nolint:gosec // under the private work directory
		if err != nil {
			return err
		}
		defer fh.Close() //nolint:errcheck // read-only
		st, err := fh.Stat()
		if err != nil {
			return err
		}
		if total += st.Size(); total > maxBytes {
			return fmt.Errorf("extracted data exceeds %d bytes", maxBytes)
		}
		h, err := hashFile(p)
		if err != nil {
			return err
		}
		format := ""
		if id := identification.Identify(fh, st.Size()); id != nil && id.Primary != "unknown" {
			format = id.Primary
		}
		out = append(out, models.ExtractedEntry{Name: textutil.Sanitize(rel), Type: "f", TypeName: "file", Size: st.Size(), StoredSize: st.Size(),
			Path: filepath.ToSlash(rel), SHA256: h.SHA256, Format: format})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

func addOverlayFindings(rep *models.Report, ex *models.Extraction) {
	var exes, other []string
	for _, e := range ex.Entries {
		if strings.HasPrefix(e.Format, "PE") || strings.HasPrefix(e.Format, "ELF") || strings.HasPrefix(e.Format, "Mach-O") {
			exes = append(exes, e.Name+" ("+e.SHA256[:12]+")")
		} else {
			other = append(other, e.Name)
		}
	}
	sum := fmt.Sprintf("%s. %d executable file(s): %s. %d other file(s).", ex.Message, len(exes), clipList(exes, 8), len(other))
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "extract.overlay-archive", Rule: "extract/overlay-archive", Class: models.ClassObservation, Category: "payload",
		Title:    ex.ArchiveFormat + " archive extracted from the executable overlay",
		Summary:  sum,
		Severity: models.SeverityInfo, Confidence: models.ConfidenceHigh,
		Rationale:  "an archive signature sits at the start of the overlay; 7-Zip ran sandboxed on a copy, and the parent re-checked and re-hashed every extracted file",
		EvidenceID: []string{},
		Action:     "Analyse each extracted executable on its own (unpackr -x <file>). UNPACKR does not run extracted content.",
	})
}

func clipList(l []string, n int) string {
	if len(l) == 0 {
		return "none"
	}
	if len(l) > n {
		return strings.Join(l[:n], ", ") + fmt.Sprintf(" and %d more", len(l)-n)
	}
	return strings.Join(l, ", ")
}

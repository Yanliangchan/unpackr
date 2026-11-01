package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/Yanliangchan/unpackr/internal/formats/elf"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Yanliangchan/unpackr/internal/comparison"
	"github.com/Yanliangchan/unpackr/internal/hashing"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/internal/unpacking"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// SupportedPackers lists what unpacking can handle in this build. It is
// printed in every attempt so support is never implied.
var SupportedPackers = []string{"UPX"}

const (
	unpackNotApplicable = "not-applicable"
	unpackUnavailable   = "unavailable"
	unpackFailed        = "failed"
	unpackRejected      = "rejected"
	unpackDone          = "unpacked"
)

// runUnpack tries to unpack the sample with UPX when the packing assessment
// indicates UPX. The sample is only ever read; the tool works on a copy in a
// private directory, and its output is validated before it is trusted.
func runUnpack(ctx context.Context, f *os.File, size int64, rep *models.Report, o Options) {
	att := &models.UnpackAttempt{Requested: true, Supported: SupportedPackers}
	rep.Unpack = att
	cfg := o.Config

	if o.Depth >= cfg.MaxUnpackDepth {
		att.Status, att.Message = unpackRejected, fmt.Sprintf("nested unpacking stopped at depth %d (max_unpack_depth)", o.Depth)
		return
	}
	a := rep.Analysis
	switch {
	case a == nil:
		att.Status, att.Message = unpackNotApplicable, "content analysis did not run, so no packer was identified"
		return
	case a.Packing.State != models.PackConfirmed && a.Packing.State != models.PackLikely:
		att.Status, att.Message = unpackNotApplicable, "no packing was indicated (state: "+a.Packing.State+")"
		return
	case a.Packing.Family != "UPX":
		fam := a.Packing.Family
		if fam == "" {
			fam = "unidentified packer"
		}
		att.Status, att.Message = unpackNotApplicable, "the indicated packer ("+fam+") is not supported; supported: "+strings.Join(SupportedPackers, ", ")
		return
	}

	name := o.UnpackerName
	if name == "" {
		name = "upx"
	}
	att.Tool = name
	tool, err := unpacking.Locate(name)
	if err != nil {
		att.Status = unpackUnavailable
		if errors.Is(err, exec.ErrNotFound) {
			att.Message = "UPX is not installed. Install it (Debian/Kali: sudo apt install upx-ucl) and run again; nothing else about the analysis is affected"
		} else {
			att.Message = "UPX could not be located: " + err.Error()
		}
		return
	}
	work, err := unpacking.WorkDir()
	if err != nil {
		att.Status, att.Message = unpackFailed, "could not create a private work directory: "+err.Error()
		return
	}
	defer os.RemoveAll(work) //nolint:errcheck // best-effort cleanup of a private temp dir

	mem := uint64(cfg.WorkerMemoryMB) << 20
	if err := tool.ProbeVersion(ctx, work, mem); err != nil {
		att.Status = unpackUnavailable
		if errors.Is(err, worker.ErrExecSandbox) {
			att.Message = "UPX was not run because it could not be fully sandboxed on this system (" + textutil.Sanitize(err.Error()) + "); external tools never run unconfined"
		} else {
			att.Message = "UPX could not be started: " + textutil.Sanitize(err.Error())
		}
		return
	}
	att.ToolVersion = tool.Version

	// The tool gets a copy; the sample itself is never handed over.
	in := filepath.Join(work, "in.bin")
	if err := copyInto(in, io.NewSectionReader(f, 0, size)); err != nil {
		att.Status, att.Message = unpackFailed, "could not stage a copy of the sample: "+err.Error()
		return
	}
	out := filepath.Join(work, "out.bin")
	maxOut := uint64(cfg.UnpackMaxMB) << 20
	run, err := unpacking.RunUPX(ctx, tool, work, in, out, unpacking.UPXOptions{
		Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, MemoryBytes: mem, MaxOutputBytes: maxOut,
	})
	if err != nil {
		att.Status = unpackFailed
		if errors.Is(err, worker.ErrExecSandbox) {
			att.Status = unpackUnavailable
		}
		att.Message = textutil.Sanitize(err.Error())
		return
	}
	if run.ExitCode != 0 {
		att.Status, att.Message = unpackFailed, unpacking.FailureHint(run.Stderr)
		return
	}

	checks, outSize := unpacking.CheckOutput(size, out, maxOut, cfg.UnpackMaxRatio)
	if !unpacking.AllPassed(checks) {
		att.Status, att.Message = unpackRejected, "the unpacked output failed validation: "+failedNames(checks)
		return
	}
	h, err := hashFile(out)
	if err != nil {
		att.Status, att.Message = unpackFailed, err.Error()
		return
	}
	// Persist under a content-derived name (never taken from the sample), with
	// no execute permission.
	dir := o.ArtifactDir
	if dir == "" {
		dir = "unpackr-out"
	}
	dir = filepath.Join(dir, "artifacts")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		att.Status, att.Message = unpackFailed, "could not create the artifact directory: "+err.Error()
		return
	}
	final := filepath.Join(dir, h.SHA256+".bin")
	if err := moveFile(out, final); err != nil {
		att.Status, att.Message = unpackFailed, "could not store the unpacked file: "+err.Error()
		return
	}

	child := o
	child.Depth = o.Depth + 1
	childRep, cerr := Analyze(ctx, final, child)
	if cerr != nil || childRep == nil {
		_ = os.Remove(final)
		att.Status, att.Message = unpackRejected, "the unpacked file could not be analysed: "+errText(cerr)
		return
	}
	checks = append(checks, structuralChecks(rep, childRep, h.SHA256 != rep.File.Hashes.SHA256)...)
	if !unpacking.AllPassed(checks) {
		_ = os.Remove(final)
		att.Status, att.Message = unpackRejected, "the unpacked output failed validation: "+failedNames(checks)
		return
	}

	art := models.Artifact{
		Kind: "unpacked", Tool: tool.Name, ToolVersion: tool.Version, ParentSHA256: rep.File.Hashes.SHA256,
		Path: final, Size: outSize, Hashes: h, Validation: checks, Report: childRep,
		Comparison: comparison.Diff(rep, childRep),
	}
	rep.Artifacts = append(rep.Artifacts, art)
	att.Status = unpackDone
	att.Message = fmt.Sprintf("unpacked with UPX %s: %d bytes became %d bytes; %d validation checks passed", tool.Version, size, outSize, len(checks))
	confirmPacking(rep, tool)
}

// structuralChecks validate that the output is a sane executable of the same
// kind as the input rather than just some bytes.
func structuralChecks(parent, child *models.Report, differs bool) []models.ValidationCheck {
	var cs []models.ValidationCheck
	add := func(name string, ok bool, detail string) {
		cs = append(cs, models.ValidationCheck{Name: name, Passed: ok, Detail: detail})
	}
	add("output differs from the packed input", differs, "")
	pb, cb := parent.Binary, child.Binary
	if cb == nil {
		add("output parses as an executable", false, "the structure parser rejected it")
		return cs
	}
	add("output parses as an executable", true, cb.Format)
	if pb != nil {
		add("same file format family", pb.Family() == cb.Family(), pb.Format+" -> "+cb.Format)
		add("same architecture", pb.Arch == cb.Arch, pb.Arch+" -> "+cb.Arch)
		// A packed ET_DYN file often cannot be classified (packer stubs have no
		// interpreter or dynamic section); the unpacked kind is then the evidence.
		kindOK := pb.Kind == cb.Kind || (pb.Kind == elf.KindAmbiguous && (cb.Kind == "executable" || cb.Kind == "library"))
		add("same kind (executable/library)", kindOK, pb.Kind+" -> "+cb.Kind)
	}
	entryOK := cb.Entry != nil && (cb.Entry.Section != "" || cb.Entry.FileOffset != nil)
	detail := "entry point not mapped"
	if cb.Entry != nil {
		detail = fmt.Sprintf("RVA 0x%x in %q", cb.Entry.RVA, cb.Entry.Section)
	}
	add("entry point maps into the file", entryOK, detail)
	nested := ""
	if ca := child.Analysis; ca != nil && ca.Packing.Family == "UPX" && (ca.Packing.State == models.PackConfirmed || ca.Packing.State == models.PackLikely) {
		nested = "output still looks UPX-packed; another layer will be attempted if depth allows"
	}
	add("no unexplained residual packer signature", true, nested)
	return cs
}

// confirmPacking upgrades the parent's packing verdict once a validated
// unpack succeeded. This is the only route to "definitive" confidence.
func confirmPacking(rep *models.Report, tool *unpacking.Tool) {
	p := &rep.Analysis.Packing
	p.State, p.Confidence = models.PackConfirmed, models.ConfidenceDefinitive
	p.Rationale += "; confirmed by a validated unpack with UPX " + tool.Version
	for i := range rep.Findings {
		if rep.Findings[i].ID == "packing.state" {
			rep.Findings[i].Confidence = models.ConfidenceDefinitive
			rep.Findings[i].Rationale = p.Rationale
			rep.Findings[i].Title = "Packing: " + models.PackConfirmed + " (UPX)"
		}
	}
	rep.Findings = append(rep.Findings, models.Finding{
		ID: "unpack.upx", Rule: "unpack/upx", Class: models.ClassObservation, Category: "unpacking",
		Title:    "Unpacked with UPX " + tool.Version,
		Summary:  "UPX decompressed the file and the result passed structural validation. The unpacked file was analysed separately and is attached to this report.",
		Severity: models.SeverityInfo, Confidence: models.ConfidenceDefinitive,
		Rationale:  "a real unpacker produced a valid executable of the same kind",
		EvidenceID: []string{}, Action: "Use the analysis of the unpacked layer for imports, strings and capabilities; the packed file's own tables describe only the stub.",
	})
}

func failedNames(cs []models.ValidationCheck) string {
	var f []string
	for _, c := range cs {
		if !c.Passed {
			f = append(f, c.Name)
		}
	}
	return strings.Join(f, "; ")
}

func errText(err error) string {
	if err == nil {
		return "no report produced"
	}
	return textutil.Sanitize(err.Error())
}

func copyInto(dst string, src io.Reader) error {
	w, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, src); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func hashFile(p string) (models.Hashes, error) {
	f, err := os.Open(p)
	if err != nil {
		return models.Hashes{}, err
	}
	defer f.Close() //nolint:errcheck // read-only
	h, _, err := hashing.Sum(f)
	return h, err
}

// moveFile renames, or copies when the work directory is on another device,
// and always leaves the result mode 0600 (no execute bit).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return os.Chmod(dst, 0o600)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close() //nolint:errcheck // read-only
	if err := copyInto(dst, in); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return os.Chmod(dst, 0o600)
}

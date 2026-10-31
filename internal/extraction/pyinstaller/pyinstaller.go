// Package pyinstaller reads PyInstaller "CArchive" bundles: the archive that
// a frozen Python program carries after its bootloader. It is a native,
// memory-safe reader (no external tool) and treats every field as hostile:
// all offsets and sizes are bounds-checked against the file, and expansion
// is capped per entry and in total.
//
// Layout (all integers big-endian):
//
//	cookie, found by its 8-byte magic near the end of the file
//	  magic "MEI\x0c\x0b\x0a\x0b\x0e", package length, TOC offset, TOC length,
//	  Python version, and (PyInstaller 2.1+) a 64-byte Python library name
//	TOC, at archiveStart+tocOffset: entries of
//	  entryLen int32, dataOffset int32, storedLen int32, rawLen int32,
//	  compressFlag byte, typeCode byte, NUL-padded name
//	data, at archiveStart+dataOffset, zlib-compressed when compressFlag == 1
//
// The archive starts at (cookie end - package length).
package pyinstaller

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Yanliangchan/unpackr/internal/identification"
	"github.com/Yanliangchan/unpackr/internal/safety"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Magic starts the cookie.
var Magic = []byte("MEI\x0c\x0b\x0a\x0b\x0e")

const (
	cookieOld = 8 + 4*4      // PyInstaller 2.0
	cookieNew = 8 + 4*4 + 64 // PyInstaller 2.1 and later
	tocFixed  = 18
	searchMax = 16 << 20 // how far from the end of the file the cookie is looked for
)

// ErrNotPyInstaller means no valid cookie was found.
var ErrNotPyInstaller = errors.New("no PyInstaller archive found")

// Limits bound extraction. The zero value is replaced by defaults.
type Limits struct {
	MaxEntries    int
	MaxTotalBytes int64
	MaxEntryBytes int64
	MaxRatio      int64 // largest raw/stored ratio accepted for one entry
}

// DefaultLimits are conservative.
func DefaultLimits() Limits {
	return Limits{MaxEntries: 20000, MaxTotalBytes: 1 << 30, MaxEntryBytes: 256 << 20, MaxRatio: 1000}
}

// Cookie is the parsed trailer.
type Cookie struct {
	Offset      int64 // file offset of the magic
	End         int64 // file offset just after the cookie
	PkgLen      int64
	TOCOffset   int64
	TOCLen      int64
	PyVersion   int
	LibName     string
	Format      string // "2.0" or "2.1+"
	ArchiveBase int64  // file offset of the archive start
}

// PythonVersion renders the version code ("311" -> "3.11").
func (c Cookie) PythonVersion() string {
	v := c.PyVersion
	if v >= 100 {
		return fmt.Sprintf("%d.%d", v/100, v%100)
	}
	if v >= 10 {
		return fmt.Sprintf("%d.%d", v/10, v%10)
	}
	return fmt.Sprint(v)
}

// FindCookie locates and validates the cookie, scanning backwards from the
// end so the last valid one wins (appended signatures and padding are
// tolerated).
func FindCookie(r io.ReaderAt, size int64) (*Cookie, error) {
	if size < cookieOld {
		return nil, ErrNotPyInstaller
	}
	start := size - searchMax
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	if _, err := r.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil, err
	}
	end := len(buf)
	for {
		i := bytes.LastIndex(buf[:end], Magic)
		if i < 0 {
			return nil, ErrNotPyInstaller
		}
		if c := parseCookie(buf[i:], start+int64(i), size); c != nil {
			return c, nil
		}
		end = i + len(Magic) - 1
		if end <= len(Magic) {
			return nil, ErrNotPyInstaller
		}
	}
}

func parseCookie(b []byte, off, size int64) *Cookie {
	if len(b) < cookieOld {
		return nil
	}
	be := binary.BigEndian
	c := &Cookie{Offset: off, PkgLen: int64(int32(be.Uint32(b[8:]))), TOCOffset: int64(int32(be.Uint32(b[12:]))),
		TOCLen: int64(int32(be.Uint32(b[16:]))), PyVersion: int(int32(be.Uint32(b[20:])))}
	// PyInstaller 2.1+ appends the Python library name; 2.0 does not. The
	// name always starts with "python" or "libpython".
	if len(b) >= cookieNew {
		name := string(bytes.TrimRight(b[24:cookieNew], "\x00"))
		if strings.HasPrefix(name, "python") || strings.HasPrefix(name, "libpython") || strings.HasPrefix(name, "Python") {
			c.LibName, c.Format, c.End = name, "2.1+", off+cookieNew
		}
	}
	if c.Format == "" {
		c.Format, c.End = "2.0", off+cookieOld
	}
	// Validate against the file before trusting anything.
	if c.PkgLen <= 0 || c.PkgLen > c.End || c.TOCOffset < 0 || c.TOCLen <= 0 || c.TOCLen > 64<<20 ||
		c.TOCOffset+c.TOCLen > c.PkgLen || c.End > size || c.PyVersion <= 0 || c.PyVersion > 9999 {
		return nil
	}
	c.ArchiveBase = c.End - c.PkgLen
	return c
}

var typeNames = map[byte]string{
	'b': "binary", 'x': "data", 'd': "dependency", 'o': "runtime option", 's': "script",
	'm': "module", 'M': "package", 'z': "pyz archive", 'Z': "pyz archive", 'l': "symlink", 'S': "splash",
}

// pycMagic maps a Python version to its bytecode magic number.
var pycMagic = map[string][4]byte{
	"3.6": {0x33, 0x0d, 0x0d, 0x0a}, "3.7": {0x42, 0x0d, 0x0d, 0x0a}, "3.8": {0x55, 0x0d, 0x0d, 0x0a},
	"3.9": {0x61, 0x0d, 0x0d, 0x0a}, "3.10": {0x6f, 0x0d, 0x0d, 0x0a}, "3.11": {0xa7, 0x0d, 0x0d, 0x0a},
	"3.12": {0xcb, 0x0d, 0x0d, 0x0a}, "3.13": {0xf3, 0x0d, 0x0d, 0x0a},
}

// pycHeader returns a header that lets bytecode tools read a bare marshalled
// code object, and whether the version is known.
func pycHeader(pyver string) ([]byte, bool) {
	m, ok := pycMagic[pyver]
	if !ok {
		return nil, false
	}
	h := append([]byte(nil), m[:]...)
	n := 12 // flags, mtime, size
	if pyver == "3.6" {
		n = 8 // mtime, size
	}
	return append(h, make([]byte, n)...), true
}

// Entry is a parsed TOC record.
type Entry struct {
	Name       string
	Type       byte
	Pos        int64 // relative to the archive base
	StoredLen  int64
	RawLen     int64
	Compressed bool
}

// ReadTOC parses the table of contents.
func ReadTOC(r io.ReaderAt, c *Cookie, maxEntries int) ([]Entry, error) {
	toc := make([]byte, c.TOCLen)
	if _, err := r.ReadAt(toc, c.ArchiveBase+c.TOCOffset); err != nil && err != io.EOF {
		return nil, fmt.Errorf("reading table of contents: %w", err)
	}
	be := binary.BigEndian
	var out []Entry
	for p := 0; p < len(toc); {
		if len(toc)-p < tocFixed {
			return out, fmt.Errorf("table of contents ends inside an entry header at byte %d", p)
		}
		el := int64(int32(be.Uint32(toc[p:])))
		if el < tocFixed || el > 4096 || int64(p)+el > int64(len(toc)) {
			return out, fmt.Errorf("entry at byte %d has an impossible length %d", p, el)
		}
		e := Entry{
			Pos:        int64(int32(be.Uint32(toc[p+4:]))),
			StoredLen:  int64(int32(be.Uint32(toc[p+8:]))),
			RawLen:     int64(int32(be.Uint32(toc[p+12:]))),
			Compressed: toc[p+16] == 1,
			Type:       toc[p+17],
		}
		name := toc[p+tocFixed : p+int(el)]
		if i := bytes.IndexByte(name, 0); i >= 0 {
			name = name[:i]
		}
		e.Name = string(name)
		out = append(out, e)
		if len(out) > maxEntries {
			return out[:maxEntries], fmt.Errorf("more than %d entries; stopping", maxEntries)
		}
		p += int(el)
	}
	return out, nil
}

// Extract reads the archive in r and writes its entries under outDir. outDir
// must already exist and be private. Entries that are unsafe or out of
// bounds are skipped with a reason; a skipped entry never aborts the rest.
func Extract(r io.ReaderAt, size int64, outDir string, lim Limits) (*models.Extraction, error) {
	d := DefaultLimits()
	if lim.MaxEntries <= 0 {
		lim.MaxEntries = d.MaxEntries
	}
	if lim.MaxTotalBytes <= 0 {
		lim.MaxTotalBytes = d.MaxTotalBytes
	}
	if lim.MaxEntryBytes <= 0 {
		lim.MaxEntryBytes = d.MaxEntryBytes
	}
	if lim.MaxRatio <= 0 {
		lim.MaxRatio = d.MaxRatio
	}
	ex := &models.Extraction{Requested: true, Kind: "PyInstaller", Supported: []string{"PyInstaller"}, Entries: []models.ExtractedEntry{}}
	c, err := FindCookie(r, size)
	if err != nil {
		ex.Status, ex.Message = "not-applicable", "no supported embedded container was found (supported: PyInstaller)"
		return ex, nil
	}
	ex.ArchiveFormat = "PyInstaller " + c.Format + " cookie"
	ex.PythonVersion = c.PythonVersion()
	ex.ArchiveOffset, ex.ArchiveLength = c.ArchiveBase, c.PkgLen
	if c.LibName != "" {
		ex.Notes = append(ex.Notes, "interpreter library: "+c.LibName)
	}
	entries, terr := ReadTOC(r, c, lim.MaxEntries)
	if terr != nil {
		ex.Notes = append(ex.Notes, terr.Error())
	}
	if len(entries) == 0 {
		ex.Status, ex.Message = "failed", "the archive has no readable table of contents"
		return ex, nil
	}
	hdr, haveHdr := pycHeader(ex.PythonVersion)

	used := map[string]bool{}
	for _, e := range entries {
		rec := models.ExtractedEntry{Name: sanitiseLabel(e.Name), Type: string(rune(e.Type)), TypeName: typeNames[e.Type], Compressed: e.Compressed,
			StoredSize: e.StoredLen, Size: e.RawLen, Offset: c.ArchiveBase + e.Pos}
		if rec.TypeName == "" {
			rec.TypeName = "unknown"
		}
		skip := func(why string) {
			rec.Skipped = why
			ex.Entries = append(ex.Entries, rec)
		}
		switch {
		case e.Type == 'd' || e.Type == 'o' || e.Type == 'l' || e.Type == 'S':
			skip("not file content (" + rec.TypeName + ")")
			continue
		case e.Pos < 0 || e.StoredLen < 0 || e.RawLen < 0 || e.Pos+e.StoredLen > c.PkgLen:
			skip("data lies outside the archive")
			continue
		case e.RawLen > lim.MaxEntryBytes || (!e.Compressed && e.StoredLen > lim.MaxEntryBytes):
			skip(fmt.Sprintf("larger than the per-entry limit of %d bytes", lim.MaxEntryBytes))
			continue
		case e.Compressed && e.StoredLen > 0 && e.RawLen/e.StoredLen > lim.MaxRatio:
			skip(fmt.Sprintf("expansion ratio above %dx (decompression-bomb guard)", lim.MaxRatio))
			continue
		case ex.TotalBytes+e.RawLen > lim.MaxTotalBytes:
			skip(fmt.Sprintf("total extraction limit of %d bytes reached", lim.MaxTotalBytes))
			continue
		}
		data, err := readEntry(r, c, e, lim.MaxEntryBytes)
		if err != nil {
			skip(err.Error())
			continue
		}
		rel, why := relPath(e.Name)
		if why != "" {
			skip(why)
			continue
		}
		if (e.Type == 's' || e.Type == 'm' || e.Type == 'M') && haveHdr {
			data = append(append([]byte(nil), hdr...), data...)
			rel += ".pyc"
		} else if e.Type == 's' || e.Type == 'm' || e.Type == 'M' {
			rel += ".bin"
			ex.Notes = append(ex.Notes, "Python "+ex.PythonVersion+" bytecode header unknown; code objects saved without a .pyc header")
		}
		final, err := place(outDir, rel, used)
		if err != nil {
			skip(err.Error())
			continue
		}
		if err := writeFile(outDir, final, data); err != nil {
			skip("could not write: " + err.Error())
			continue
		}
		sum := sha256.Sum256(data)
		rec.SHA256 = hex.EncodeToString(sum[:])
		rec.Path = filepath.ToSlash(final)
		rec.Size = int64(len(data))
		rec.Format = identification.Identify(bytes.NewReader(data), int64(len(data))).Primary
		ex.TotalBytes += int64(len(data))
		ex.Entries = append(ex.Entries, rec)
	}
	ex.Status = "extracted"
	n := 0
	for _, e := range ex.Entries {
		if e.Path != "" {
			n++
		}
	}
	ex.Message = fmt.Sprintf("PyInstaller archive (Python %s): %d of %d entries extracted, %d bytes", ex.PythonVersion, n, len(ex.Entries), ex.TotalBytes)
	if n == 0 {
		ex.Status, ex.Message = "failed", "the archive was recognised but no entry could be extracted safely"
	}
	return ex, nil
}

// readEntry returns the raw bytes of one entry, decompressing when needed. A
// decompressed size that disagrees with the TOC is an error, and output is
// never allowed past the declared size.
func readEntry(r io.ReaderAt, c *Cookie, e Entry, max int64) ([]byte, error) {
	sr := io.NewSectionReader(r, c.ArchiveBase+e.Pos, e.StoredLen)
	if !e.Compressed {
		b := make([]byte, e.StoredLen)
		if _, err := io.ReadFull(sr, b); err != nil {
			return nil, fmt.Errorf("truncated data: %w", err)
		}
		return b, nil
	}
	zr, err := zlib.NewReader(sr)
	if err != nil {
		return nil, fmt.Errorf("not valid zlib data: %v", err)
	}
	defer zr.Close() //nolint:errcheck // reader over memory
	limit := e.RawLen
	if limit > max {
		limit = max
	}
	b, err := io.ReadAll(io.LimitReader(zr, limit+1))
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %v", err)
	}
	if int64(len(b)) != e.RawLen {
		return nil, fmt.Errorf("decompressed to %d bytes but the table says %d", len(b), e.RawLen)
	}
	return b, nil
}

// relPath turns an archive name into a safe relative path, or explains why it
// cannot. Traversal and absolute names are refused rather than rewritten, so
// an entry never lands somewhere its name did not say.
func relPath(name string) (string, string) {
	n := strings.ReplaceAll(name, "\\", "/")
	if n == "" || strings.ContainsRune(n, 0) {
		return "", "empty or malformed name"
	}
	if strings.HasPrefix(n, "/") || (len(n) >= 2 && n[1] == ':') {
		return "", "absolute path in entry name"
	}
	var parts []string
	for _, p := range strings.Split(n, "/") {
		switch p {
		case "", ".":
			continue
		case "..":
			return "", "path traversal (..) in entry name"
		}
		parts = append(parts, sanitiseComponent(p))
	}
	if len(parts) == 0 {
		return "", "empty path"
	}
	return filepath.Join(parts...), ""
}

func sanitiseComponent(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-', r == '+':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 120 {
		out = out[:120]
	}
	if out == "" || out == "." || out == ".." {
		return "_"
	}
	return out
}

// sanitiseLabel keeps entry names printable for the report.
func sanitiseLabel(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// place chooses a unique destination under root for rel, guaranteed to stay
// inside root.
func place(root, rel string, used map[string]bool) (string, error) {
	cand := rel
	for i := 2; used[strings.ToLower(cand)]; i++ {
		ext := filepath.Ext(rel)
		cand = fmt.Sprintf("%s_%d%s", strings.TrimSuffix(rel, ext), i, ext)
		if i > 1000 {
			return "", errors.New("too many name collisions")
		}
	}
	if _, err := safety.SecureJoin(root, cand); err != nil {
		return "", err
	}
	used[strings.ToLower(cand)] = true
	return cand, nil
}

// writeFile creates rel under root with mode 0600, creating parents 0700. It
// refuses to follow or replace anything that already exists.
func writeFile(root, rel string, data []byte) error {
	full, err := safety.SecureJoin(root, rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

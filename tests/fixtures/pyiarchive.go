package fixtures

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
)

// PYIEntry describes one archive entry. The override fields let tests write
// lying table values.
type PYIEntry struct {
	Name     string
	Type     byte // 's', 'm', 'b', 'x', 'z' ...
	Data     []byte
	Compress bool

	Pos, StoredLen, RawLen *int32
}

// PYISpec describes a synthetic PyInstaller CArchive.
type PYISpec struct {
	PyVersion int // e.g. 311
	LibName   string
	OldCookie bool // PyInstaller 2.0 layout without the library name
	Entries   []PYIEntry
}

// BuildPyInstaller returns archive bytes: entry data, table of contents and
// cookie. Appending it to any executable produces a file shaped like a frozen
// Python program. The content is inert test data.
func BuildPyInstaller(s PYISpec) []byte {
	if s.PyVersion == 0 {
		s.PyVersion = 311
	}
	be := binary.BigEndian
	var data bytes.Buffer
	type rec struct {
		pos, stored, raw int32
		compress         byte
	}
	var recs []rec
	for _, e := range s.Entries {
		pos := int32(data.Len())
		payload := e.Data
		comp := byte(0)
		if e.Compress {
			var zb bytes.Buffer
			zw := zlib.NewWriter(&zb)
			_, _ = zw.Write(e.Data)
			_ = zw.Close()
			payload, comp = zb.Bytes(), 1
		}
		data.Write(payload)
		recs = append(recs, rec{pos, int32(len(payload)), int32(len(e.Data)), comp})
	}
	tocPos := int32(data.Len())
	var toc bytes.Buffer
	for i, e := range s.Entries {
		r := recs[i]
		if e.Pos != nil {
			r.pos = *e.Pos
		}
		if e.StoredLen != nil {
			r.stored = *e.StoredLen
		}
		if e.RawLen != nil {
			r.raw = *e.RawLen
		}
		name := append([]byte(e.Name), 0)
		for (18+len(name))%16 != 0 {
			name = append(name, 0)
		}
		hdr := make([]byte, 18)
		be.PutUint32(hdr[0:], uint32(18+len(name)))
		be.PutUint32(hdr[4:], uint32(r.pos))
		be.PutUint32(hdr[8:], uint32(r.stored))
		be.PutUint32(hdr[12:], uint32(r.raw))
		hdr[16], hdr[17] = r.compress, e.Type
		toc.Write(hdr)
		toc.Write(name)
	}
	data.Write(toc.Bytes())
	cookieLen := 88
	if s.OldCookie {
		cookieLen = 24
	}
	total := int32(data.Len() + cookieLen)
	cookie := make([]byte, cookieLen)
	copy(cookie, "MEI\x0c\x0b\x0a\x0b\x0e")
	be.PutUint32(cookie[8:], uint32(total))
	be.PutUint32(cookie[12:], uint32(tocPos))
	be.PutUint32(cookie[16:], uint32(toc.Len()))
	be.PutUint32(cookie[20:], uint32(s.PyVersion))
	if !s.OldCookie {
		lib := s.LibName
		if lib == "" {
			lib = "libpython3.11.so.1.0"
		}
		copy(cookie[24:], lib)
	}
	data.Write(cookie)
	return data.Bytes()
}

// Int32 returns a pointer for the override fields.
func Int32(v int32) *int32 { return &v }

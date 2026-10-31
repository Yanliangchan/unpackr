package engine

import (
	"io"
	"os"
)

// sectionReader returns a reader over the whole file that does not move the
// descriptor's offset (the descriptor is shared with workers).
func sectionReader(f *os.File, size int64) io.Reader { return io.NewSectionReader(f, 0, size) }

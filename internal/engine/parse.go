package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Yanliangchan/unpackr/internal/formats/elf"
	"github.com/Yanliangchan/unpackr/internal/formats/macho"
	"github.com/Yanliangchan/unpackr/internal/formats/pe"
	"github.com/Yanliangchan/unpackr/internal/worker"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

// TaskParse parses the executable structure inside a sandboxed worker.
const TaskParse = "parse"

// MaxParseBytes bounds how much of a file is loaded for structure parsing.
// Larger files are parsed from their first MaxParseBytes and flagged.
const MaxParseBytes = 256 << 20

// ParseParams selects the parser.
type ParseParams struct {
	Family string `json:"family"`
}

func init() {
	worker.Register(TaskParse, func(ctx context.Context, in io.ReaderAt, size int64, raw json.RawMessage) (any, error) {
		var p ParseParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		n := size
		truncated := false
		if n > MaxParseBytes {
			n, truncated = MaxParseBytes, true
		}
		data, err := io.ReadAll(io.NewSectionReader(in, 0, n))
		if err != nil {
			return nil, err
		}
		var b *models.Binary
		switch p.Family {
		case "pe":
			b, err = pe.Parse(data)
		case "elf":
			b, err = elf.Parse(data)
		case "macho":
			b, err = macho.Parse(data)
		default:
			return nil, fmt.Errorf("no structure parser for family %q", p.Family)
		}
		if err != nil {
			return nil, err
		}
		b.Truncated = truncated
		if truncated {
			b.Anomalies = append(b.Anomalies, fmt.Sprintf("file is %d bytes; only the first %d were parsed", size, n))
		}
		return b, nil
	})
}

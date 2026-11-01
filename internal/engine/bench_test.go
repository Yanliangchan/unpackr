package engine

import (
	"os"
	"testing"

	"github.com/Yanliangchan/unpackr/tests/fixtures"
)

// BenchmarkAnalyzeBytes measures the content-analysis core (everything the
// worker does after parsing) on a real 2+ MB Go executable. Run with
// `make bench`.
func BenchmarkAnalyzeBytes(b *testing.B) {
	path := fixtures.GoBinary(b, "linux", "amd64")
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	for _, skip := range []bool{false, true} {
		name := "info"
		if skip {
			name = "quick"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			for i := 0; i < b.N; i++ {
				analyzeBytes(data, "elf", nil, nil, skip)
			}
		})
	}
}

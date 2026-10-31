// Package content measures and extracts raw content: entropy, strings and
// indicator-like values. Everything here operates on bytes and is
// format-agnostic.
package content

import "math"

// Entropy returns the Shannon entropy of b in bits per byte (0 to 8).
func Entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var e float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return math.Round(e*1000) / 1000
}

// Slice returns data[off:off+size] clipped to the buffer, or nil if it lies
// entirely outside.
func Slice(data []byte, off, size uint64) []byte {
	if off >= uint64(len(data)) || size == 0 {
		return nil
	}
	end := off + size
	if end < off || end > uint64(len(data)) {
		end = uint64(len(data))
	}
	return data[off:end]
}

package analysis

import (
	"regexp"
	"testing"
)

func TestFindAnchoredMatchesFullScan(t *testing.T) {
	re := regexp.MustCompile(`(?:Ubuntu |Debian )?clang version [0-9][0-9.]*`)
	cases := [][]byte{
		[]byte("xx clang version 14.0.0 yy"),
		[]byte("junk clang version  clang version 15.0.7-2"),
		[]byte("zzUbuntu clang version 18.1.3 tail"),
		[]byte("clang version 9"),
		[]byte("nothing here"),
		[]byte("clang version "),
	}
	for _, d := range cases {
		in := &Input{Data: d}
		wo, wm := in.FindRegexp(re)
		go1, gm := in.FindAnchored(re, "clang version ", 7, 64)
		if wo != go1 || wm != gm {
			t.Errorf("%q: anchored (%d,%q) != full (%d,%q)", d, go1, gm, wo, wm)
		}
	}
}

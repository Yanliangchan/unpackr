package content

import (
	"math/rand"
	"regexp"
	"testing"
)

// A failed guard must imply that the pattern cannot match.
func TestGuardsAreNecessary(t *testing.T) {
	alphabet := []string{"a", "Z", "0", "9", ".", "@", ":", "\\", "/", " ", "\t", "-", "_", "$", "http", "://", "HKLM", "cmd", "C:", "etc", "tmp", "net user", "curl -", "x.com"}
	rng := rand.New(rand.NewSource(1))
	checks := []struct {
		name string
		re   *regexp.Regexp
		ok   func(guards) bool
	}{
		{"ipv4", reIPv4, func(g guards) bool { return g.dot }},
		{"domain", reDomain, func(g guards) bool { return g.dot }},
		{"email", reEmail, func(g guards) bool { return g.at }},
		{"winpath", reWinPath, func(g guards) bool { return g.drive }},
		{"unc", reUNC, func(g guards) bool { return g.unc }},
		{"unix", reUnix, func(g guards) bool { return g.slash }},
		{"reg", reReg, func(g guards) bool { return g.bs }},
		{"regrun", reRegRun, func(g guards) bool { return g.bs }},
		{"cmd", reCmd, func(g guards) bool { return g.space }},
	}
	for n := 0; n < 200000; n++ {
		s := ""
		for i, l := 0, rng.Intn(10); i < l; i++ {
			s += alphabet[rng.Intn(len(alphabet))]
		}
		g := guardsFor(s)
		for _, c := range checks {
			if !c.ok(g) && c.re.MatchString(s) {
				t.Fatalf("%s matches %q although its guard is false", c.name, s)
			}
		}
	}
}

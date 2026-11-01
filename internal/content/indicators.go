package content

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// TLDs are the top-level domains recognised as domain indicators. A short,
// deliberate list: every extra entry adds false positives from symbol names.
const TLDs = "com|net|org|info|biz|io|co|ru|cn|xyz|top|cc|tk|ml|ga|cf|gq|de|uk|fr|jp|us|ly|br|eu|onion|club|site|online|shop|pw|vip|ir|kp|ua|nl|pl|es|au|ca|ch|se|kr|tw|hk|sg|vn|th|tr|za|mx|ar|tv|ws|su"

// MaxIndicators bounds the indicator list.
const MaxIndicators = 2000

var (
	reURL     = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\\^|{})` + "`" + `]{3,300}`)
	reIPv4    = regexp.MustCompile(`(?:^|[^0-9.])((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(?:$|[^0-9.]|\.(?:[^0-9]|$))`)
	reDomain  = regexp.MustCompile(`\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:` + TLDs + `))\b`)
	reEmail   = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b`)
	reWinPath = regexp.MustCompile(`(?i)\b[a-z]:\\(?:[^\\/:*?"<>|\r\n\x00]{1,64}\\)*[^\\/:*?"<>|\r\n\x00]{1,64}`)
	reUNC     = regexp.MustCompile(`\\\\[A-Za-z0-9_$-][A-Za-z0-9_.$-]{1,62}\\[A-Za-z0-9_.$-]{1,64}(?:\\[A-Za-z0-9_.$-]{1,64}){0,4}`)
	reUnix    = regexp.MustCompile(`(?:^|[\s"'=:])(/(?:etc|bin|sbin|tmp|dev|proc|var|usr|opt|home|root)/[A-Za-z0-9_./-]{2,120})`)
	reReg     = regexp.MustCompile(`(?i)\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\[^\x00\r\n"]{3,200}`)
	reRegRun  = regexp.MustCompile(`(?i)software\\microsoft\\windows(?: nt)?\\currentversion\\(?:run|runonce|winlogon|image file execution options)[^\x00\r\n"]{0,100}`)
	reCmd     = regexp.MustCompile(`(?i)\b(?:cmd(?:\.exe)?\s+/[ck]|powershell(?:\.exe)?\s+-\w+|wscript(?:\.exe)?\s|cscript(?:\.exe)?\s|regsvr32(?:\.exe)?\s|rundll32(?:\.exe)?\s|schtasks(?:\.exe)?\s+/|certutil(?:\.exe)?\s+-|bitsadmin(?:\.exe)?\s+/|mshta(?:\.exe)?\s|vssadmin(?:\.exe)?\s+delete|wmic(?:\.exe)?\s+\w+|net(?:\.exe)?\s+user\s|curl\s+-|wget\s+-)[^\x00]{0,120}`)
	// A dotted import path such as golang.org/x/net/context is a module name,
	// not a network indicator.
	reModulePath = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]+/[A-Za-z0-9_./~-]+$`)
)

// benignHosts are namespace and schema hosts that appear in nearly every
// binary and carry no investigative value on their own.
var benignHosts = map[string]bool{
	"w3.org": true, "www.w3.org": true, "schemas.microsoft.com": true, "schemas.openxmlformats.org": true,
	"purl.org": true, "xmlsoap.org": true, "schemas.xmlsoap.org": true, "example.com": true, "example.org": true,
	"localhost": true,
}

type key struct{ typ, val string }

// ExtractIndicators scans strings for IOC-shaped values. Values are
// de-duplicated; Count is the number of occurrences and Offset the first.
func ExtractIndicators(hits []Hit, sectionOf func(off int64) string) []models.Indicator {
	seen := map[key]*models.Indicator{}
	var order []key
	add := func(typ, val string, h Hit, note string) {
		k := key{typ, val}
		if ind, ok := seen[k]; ok {
			ind.Count++
			return
		}
		if len(order) >= MaxIndicators {
			return
		}
		seen[k] = &models.Indicator{Type: typ, Value: val, Count: 1, Offset: h.Offset, Encoding: h.Enc, Section: sectionOf(h.Offset), Note: note}
		order = append(order, k)
	}
	for _, h := range hits {
		t := h.Text
		if len(t) < 6 {
			continue
		}
		var urlSpans [][]int
		if strings.Contains(t, "://") {
			urlSpans = reURL.FindAllStringIndex(t, -1)
		}
		for _, sp := range urlSpans {
			u := strings.TrimRight(t[sp[0]:sp[1]], `.,;:)]}'"`)
			if host := hostOf(u); benignHosts[host] {
				continue
			}
			add("url", u, h, "")
		}
		// Hosts inside URLs are already covered; look for others in the rest.
		rest := t
		for i := len(urlSpans) - 1; i >= 0; i-- {
			rest = rest[:urlSpans[i][0]] + " " + rest[urlSpans[i][1]:]
		}
		g := guardsFor(rest)
		for _, m := range g.ipv4(rest) {
			ip := net.ParseIP(m[1])
			if ip == nil || ip.IsUnspecified() {
				continue
			}
			note := ""
			switch {
			case ip.IsLoopback():
				note = "loopback"
			case ip.IsPrivate():
				note = "private range"
			case ip.IsLinkLocalUnicast():
				note = "link-local"
			default:
				note = "could also be a version number"
			}
			add("ipv4", m[1], h, note)
		}
		if g.tld && !reModulePath.MatchString(rest) {
			for _, m := range reDomain.FindAllStringSubmatchIndex(rest, -1) {
				d := rest[m[2]:m[3]]
				// Skip identifiers such as system.net.http or file names.
				if m[3] < len(rest) && (rest[m[3]] == '.' || rest[m[3]] == '(') {
					continue
				}
				if benignHosts[d] || strings.HasPrefix(d, "www.w3.") {
					continue
				}
				// Symbol tables and glued string pools produce many
				// identifier-shaped matches (eq.io, itab.net). Accept a domain
				// only when its first label is at least three characters and
				// either the string is short or is the domain itself.
				if i := strings.IndexByte(d, '.'); i < 3 {
					continue
				}
				// A domain in prose is preceded by a separator. A preceding
				// dot, colon, star or identifier character means this is
				// part of a symbol such as type:.hash.net or *eq.io.
				if m[2] > 0 && !strings.ContainsRune(" \t\"'=(,<>/@[{;", rune(rest[m[2]-1])) {
					continue
				}
				if len(rest) > 100 && strings.TrimSpace(rest) != d {
					continue
				}
				add("domain", d, h, "domain-shaped string; verify it is not an identifier")
			}
		}
		for _, e := range g.find(g.at, reEmail, rest) {
			add("email", e, h, "")
		}
		for _, p := range g.find(g.drive, reWinPath, rest) {
			add("windows-path", p, h, "")
		}
		for _, p := range g.find(g.unc, reUNC, rest) {
			add("windows-path", p, h, "UNC path")
		}
		for _, m := range g.unix(rest) {
			add("unix-path", m[1], h, "")
		}
		for _, r := range g.find(g.bs, reReg, rest) {
			add("registry", r, h, "")
		}
		for _, r := range g.find(g.bs, reRegRun, rest) {
			add("registry", r, h, "autorun / persistence location")
		}
		for _, c := range g.find(g.space, reCmd, rest) {
			add("command", strings.TrimSpace(c), h, "")
		}
	}
	out := make([]models.Indicator, 0, len(order))
	for _, k := range order {
		ind := *seen[k]
		if ind.Count >= 50 {
			if ind.Note != "" {
				ind.Note += "; "
			}
			ind.Note += "occurs very often, so likely library boilerplate"
		}
		out = append(out, ind)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Offset < out[j].Offset
	})
	return out
}

func hostOf(u string) string {
	u = u[strings.Index(u, "://")+3:]
	if i := strings.IndexAny(u, "/:?#"); i >= 0 {
		u = u[:i]
	}
	return strings.ToLower(u)
}

// guards records cheap necessary conditions for each indicator pattern. Every
// pattern contains the literal it is guarded by in all of its alternatives, so
// a failed guard proves there is no match and the regexp is skipped. This is
// an optimisation only; TestGuardsAreNecessary checks it cannot hide a match.
type guards struct{ dot, tld, at, drive, unc, slash, bs, space bool }

func guardsFor(s string) guards {
	g := guards{
		dot:   strings.IndexByte(s, '.') >= 0,
		at:    strings.IndexByte(s, '@') >= 0,
		drive: strings.Contains(s, ":\\"),
		unc:   strings.Contains(s, "\\\\"),
		slash: strings.IndexByte(s, '/') >= 0,
		bs:    strings.IndexByte(s, '\\') >= 0,
		space: strings.ContainsAny(s, " \t\n\f\r"),
	}
	g.tld = g.dot && hasTLDAfterDot(s)
	return g
}

var tldSet, tldMaxLen = func() (map[string]bool, int) {
	m, longest := map[string]bool{}, 0
	for _, t := range strings.Split(TLDs, "|") {
		m[t] = true
		longest = max(longest, len(t))
	}
	return m, longest
}()

func isWord(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// hasTLDAfterDot is the necessary condition for reDomain: its final "\.TLD\b"
// means some dot is followed by a run of word characters that is exactly one
// of the TLDs (the run must end at a word boundary).
func hasTLDAfterDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '.' {
			continue
		}
		j := i + 1
		for j < len(s) && isWord(s[j]) {
			j++
		}
		if j-i-1 <= tldMaxLen && tldSet[s[i+1:j]] {
			return true
		}
	}
	return false
}

func (g guards) find(ok bool, re *regexp.Regexp, s string) []string {
	if !ok {
		return nil
	}
	return re.FindAllString(s, -1)
}

func (g guards) ipv4(s string) [][]string {
	if !g.dot {
		return nil
	}
	return reIPv4.FindAllStringSubmatch(s, -1)
}

func (g guards) unix(s string) [][]string {
	if !g.slash {
		return nil
	}
	return reUnix.FindAllStringSubmatch(s, -1)
}

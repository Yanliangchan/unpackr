package content

import (
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// MaxIndicators bounds the indicator list.
const MaxIndicators = 2000

var (
	reURL     = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\\^|{})` + "`" + `]{3,300}`)
	reIPv4    = regexp.MustCompile(`(?:^|[^0-9.])((?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))(?:$|[^0-9.]|\.(?:[^0-9]|$))`)
	reDomain  = regexp.MustCompile(`\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|io|co|ru|cn|xyz|top|cc|tk|ml|ga|cf|gq|de|uk|fr|jp|us|tv|ws|su|ly|br|eu|onion|club|site|online|shop|pw|vip|ir|kp|ua|nl|pl|es|au|ca|ch|se|kr|tw|hk|sg|vn|th|tr|za|mx|ar))\b`)
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
		urlSpans := reURL.FindAllStringIndex(t, -1)
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
		for _, m := range reIPv4.FindAllStringSubmatch(rest, -1) {
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
		if !reModulePath.MatchString(rest) {
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
		for _, e := range reEmail.FindAllString(rest, -1) {
			add("email", e, h, "")
		}
		for _, p := range reWinPath.FindAllString(rest, -1) {
			add("windows-path", p, h, "")
		}
		for _, p := range reUNC.FindAllString(rest, -1) {
			add("windows-path", p, h, "UNC path")
		}
		for _, m := range reUnix.FindAllStringSubmatch(rest, -1) {
			add("unix-path", m[1], h, "")
		}
		for _, r := range reReg.FindAllString(rest, -1) {
			add("registry", r, h, "")
		}
		for _, r := range reRegRun.FindAllString(rest, -1) {
			add("registry", r, h, "autorun / persistence location")
		}
		for _, c := range reCmd.FindAllString(rest, -1) {
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

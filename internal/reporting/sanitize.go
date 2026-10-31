package reporting

import (
	"reflect"
	"regexp"

	"github.com/Yanliangchan/unpackr/internal/content"
	"github.com/Yanliangchan/unpackr/internal/textutil"
	"github.com/Yanliangchan/unpackr/pkg/models"
)

var (
	reURLText    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s"'<>\\^|{}` + "`" + `)]{3,300}`)
	reIPText     = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`)
	reDomainText = regexp.MustCompile(`\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:` + content.TLDs + `)\b`)
	reEmailText  = regexp.MustCompile(`\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b`)
)

// DefangText defangs network-looking fragments inside free text: URLs, IPv4
// addresses, domains and e-mail addresses, so that nothing in a report can be
// clicked, auto-linked or resolved by accident. The operation is idempotent.
func DefangText(s string) string {
	s = reURLText.ReplaceAllStringFunc(s, func(u string) string { return Defang("url", u) })
	s = reEmailText.ReplaceAllStringFunc(s, func(u string) string { return Defang("email", u) })
	s = reIPText.ReplaceAllStringFunc(s, func(u string) string { return Defang("ipv4", u) })
	s = reDomainText.ReplaceAllStringFunc(s, func(u string) string { return Defang("domain", u) })
	return s
}

// safeText is what every report string passes through.
func safeText(s string) string { return DefangText(textutil.Sanitize(s)) }

// sanitized returns a deep copy of r in which every string has been made safe
// for output: control characters, escape sequences and bidirectional
// overrides are neutralised, and (when defang is true) network-looking text is
// defanged. Renderers only ever see this copy, so a field added to the model
// later cannot bypass the protection by being forgotten in a template. All
// strings in a report ultimately come from a hostile file or from a process
// that has just parsed one, enumerations included.
func sanitized(r *models.Report, defang bool) *models.Report {
	fn := textutil.Sanitize
	if defang {
		fn = safeText
	}
	out := reflect.New(reflect.TypeOf(*r))
	copyValue(out.Elem(), reflect.ValueOf(*r), fn)
	return out.Interface().(*models.Report)
}

func copyValue(dst, src reflect.Value, fn func(string) string) {
	switch src.Kind() {
	case reflect.String:
		dst.SetString(fn(src.String()))
	case reflect.Pointer:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.New(src.Type().Elem()))
		copyValue(dst.Elem(), src.Elem(), fn)
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			if dst.Field(i).CanSet() {
				copyValue(dst.Field(i), src.Field(i), fn)
			}
		}
	case reflect.Slice:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.MakeSlice(src.Type(), src.Len(), src.Len()))
		for i := 0; i < src.Len(); i++ {
			copyValue(dst.Index(i), src.Index(i), fn)
		}
	case reflect.Map:
		if src.IsNil() {
			return
		}
		dst.Set(reflect.MakeMapWithSize(src.Type(), src.Len()))
		for _, k := range src.MapKeys() {
			v := reflect.New(src.Type().Elem()).Elem()
			copyValue(v, src.MapIndex(k), fn)
			key := reflect.New(k.Type()).Elem()
			copyValue(key, k, fn)
			dst.SetMapIndex(key, v)
		}
	case reflect.Array:
		for i := 0; i < src.Len(); i++ {
			copyValue(dst.Index(i), src.Index(i), fn)
		}
	default:
		dst.Set(src) // numbers, bools, time.Time (a struct of unexported fields is copied by Set below)
	}
}

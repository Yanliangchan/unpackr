package artvault

import (
	"fmt"
	"math"
	"os"
	"strings"
)

// Artwork files stay plain printable ASCII so they can never carry terminal
// control sequences. Colour is added here, at print time, from a named style.

// Depth is how many colours the terminal can show.
type Depth int

// Colour depths, lowest first.
const (
	DepthNone  Depth = iota // no colour: print the artwork as is
	DepthBasic              // the 16 ANSI colours
	Depth256                // the 256-colour palette
	DepthTrue               // 24-bit colour
)

// DetectDepth reads the usual environment conventions. It does not decide
// whether colour is wanted at all; the caller does that (TTY, NO_COLOR).
func DetectDepth() Depth {
	ct := strings.ToLower(os.Getenv("COLORTERM"))
	if strings.Contains(ct, "truecolor") || strings.Contains(ct, "24bit") {
		return DepthTrue
	}
	if strings.Contains(os.Getenv("TERM"), "256color") {
		return Depth256
	}
	return DepthBasic
}

type rgb struct{ r, g, b float64 }

type style struct {
	stops []rgb    // top to bottom
	basic []string // SGR codes for 16-colour terminals, top to bottom
	hue   bool     // rainbow: colour follows a diagonal hue sweep instead of stops
}

var styles = map[string]style{
	"fire":    {stops: []rgb{{255, 225, 80}, {255, 120, 0}, {200, 20, 20}}, basic: []string{"93", "33", "91", "31"}},
	"ice":     {stops: []rgb{{200, 240, 255}, {80, 190, 255}, {40, 90, 220}}, basic: []string{"97", "96", "36", "94"}},
	"matrix":  {stops: []rgb{{150, 255, 170}, {0, 230, 70}, {0, 110, 40}}, basic: []string{"92", "32", "32", "2;32"}},
	"sunset":  {stops: []rgb{{255, 200, 90}, {255, 100, 120}, {150, 60, 200}}, basic: []string{"93", "91", "95", "35"}},
	"toxic":   {stops: []rgb{{230, 255, 0}, {120, 255, 0}, {0, 170, 60}}, basic: []string{"93", "92", "32", "32"}},
	"gold":    {stops: []rgb{{255, 240, 160}, {255, 200, 40}, {190, 120, 10}}, basic: []string{"97", "93", "33", "33"}},
	"plasma":  {stops: []rgb{{255, 90, 255}, {150, 90, 255}, {60, 200, 255}}, basic: []string{"95", "35", "94", "96"}},
	"ocean":   {stops: []rgb{{120, 255, 235}, {40, 170, 255}, {40, 70, 190}}, basic: []string{"96", "36", "94", "34"}},
	"rainbow": {hue: true, basic: []string{"91", "93", "92", "96", "94", "95"}},
	"cyan":    {stops: []rgb{{0, 190, 200}}, basic: []string{"36"}},
}

// StyleNames lists the available styles in a stable order.
func StyleNames() []string {
	return []string{"fire", "ice", "matrix", "sunset", "toxic", "gold", "plasma", "ocean", "rainbow", "cyan"}
}

var categoryStyle = map[string]string{
	"compiler": "sunset", "crypto": "matrix", "executable": "ocean", "humour": "rainbow",
	"low-level": "ice", "os": "toxic", "reverse": "plasma", "picture": "rainbow",
}

// EffectiveStyle is the style the banner asks for, else its category's, else
// plain cyan (the colour custom artwork has always had).
func (b Banner) EffectiveStyle() string {
	if _, ok := styles[b.Style]; ok {
		return b.Style
	}
	if s, ok := categoryStyle[b.Category]; ok && !b.Custom {
		return s
	}
	return "cyan"
}

// Paint returns the artwork with colour applied, one reset per line so colour
// can never run on into later output. With DepthNone it is exactly Text().
func Paint(b Banner, name string, d Depth) string {
	if d == DepthNone {
		return b.Text()
	}
	st, ok := styles[name]
	if !ok {
		st = styles[b.EffectiveStyle()]
	}
	rows := len(b.Lines)
	var out strings.Builder
	for y, line := range b.Lines {
		if y > 0 {
			out.WriteByte('\n')
		}
		t := 0.0
		if rows > 1 {
			t = float64(y) / float64(rows-1)
		}
		last := ""
		for x := 0; x < len(line); x++ {
			c := line[x]
			if c == ' ' {
				out.WriteByte(c)
				continue
			}
			code := sgr(st, t, x, y, d)
			if code != last {
				out.WriteString(code)
				last = code
			}
			out.WriteByte(c)
		}
		if last != "" {
			out.WriteString("\x1b[0m")
		}
	}
	return out.String()
}

func sgr(st style, t float64, x, y int, d Depth) string {
	if d == DepthBasic {
		if st.hue {
			return "\x1b[" + st.basic[((y+x/6)%len(st.basic)+len(st.basic))%len(st.basic)] + "m"
		}
		i := int(math.Round(t * float64(len(st.basic)-1)))
		return "\x1b[" + st.basic[i] + "m"
	}
	var c rgb
	if st.hue {
		c = hsv(math.Mod(float64(y*22+x*3), 360))
	} else {
		c = blend(st.stops, t)
	}
	if d == Depth256 {
		return fmt.Sprintf("\x1b[38;5;%dm", 16+36*q6(c.r)+6*q6(c.g)+q6(c.b))
	}
	return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", int(c.r), int(c.g), int(c.b))
}

func q6(v float64) int { return int(v*5/255 + 0.5) }

func blend(stops []rgb, t float64) rgb {
	if len(stops) == 1 {
		return stops[0]
	}
	f := t * float64(len(stops)-1)
	i := int(f)
	if i >= len(stops)-1 {
		return stops[len(stops)-1]
	}
	u := f - float64(i)
	a, b := stops[i], stops[i+1]
	return rgb{a.r + (b.r-a.r)*u, a.g + (b.g-a.g)*u, a.b + (b.b-a.b)*u}
}

// hsv converts a hue in degrees (full saturation, bright) to RGB.
func hsv(h float64) rgb {
	x := 1 - math.Abs(math.Mod(h/60, 2)-1)
	var r, g, b float64
	switch {
	case h < 60:
		r, g = 1, x
	case h < 120:
		r, g = x, 1
	case h < 180:
		g, b = 1, x
	case h < 240:
		g, b = x, 1
	case h < 300:
		r, b = x, 1
	default:
		r, b = 1, x
	}
	m := 0.25 // keep every colour readable on a dark background
	return rgb{(m + (1-m)*r) * 255, (m + (1-m)*g) * 255, (m + (1-m)*b) * 255}
}

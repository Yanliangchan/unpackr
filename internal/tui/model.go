package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Options configure the view.
type Options struct {
	// Color enables styling. Layout and content are identical without it.
	Color bool
}

// Model is the inspect view.
type Model struct {
	r      *models.Report
	tabs   []tab
	active int

	cursor []int // per tab: index into the visible rows
	top    []int // per tab: first visible row
	filter []string
	// pin restricts a tab to the given row keys (evidence of one finding).
	pin    []map[string]bool
	pinned []string // description of the pin for the status line

	searching bool
	input     string
	showHelp  bool

	w, h  int
	color bool
	// Quit is true once the user asked to leave.
	Quit bool
}

// New builds the view for a report. The report must already be sanitised.
func New(r *models.Report, o Options) *Model {
	tabs := buildTabs(r)
	return &Model{
		r: r, tabs: tabs, color: o.Color, w: 100, h: 30,
		cursor: make([]int, len(tabs)), top: make([]int, len(tabs)),
		filter: make([]string, len(tabs)), pin: make([]map[string]bool, len(tabs)), pinned: make([]string, len(tabs)),
	}
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

func (m *Model) visible(t int) []row {
	var out []row
	f := strings.ToLower(m.filter[t])
	for _, r := range m.tabs[t].rows {
		if m.pin[t] != nil && !m.pin[t][r.key] {
			continue
		}
		if f != "" && !strings.Contains(r.search, f) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m *Model) listHeight() int {
	// header(2) + tabs(1) + blank(1) + footer(2) leaves the rest for list and detail.
	avail := m.h - 6
	if avail < 6 {
		return max(avail, 2)
	}
	return avail * 45 / 100
}

func (m *Model) clamp() {
	rows := m.visible(m.active)
	c := &m.cursor[m.active]
	*c = max(0, min(*c, len(rows)-1))
	lh := m.listHeight()
	t := &m.top[m.active]
	if *c < *t {
		*t = *c
	}
	if *c >= *t+lh {
		*t = *c - lh + 1
	}
	*t = max(0, *t)
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.clamp()
	case tea.KeyMsg:
		if m.searching {
			m.searchKey(msg)
			return m, nil
		}
		return m.key(msg)
	}
	return m, nil
}

func (m *Model) searchKey(k tea.KeyMsg) {
	switch k.Type {
	case tea.KeyEnter:
		m.filter[m.active] = m.input
		m.searching = false
		m.cursor[m.active], m.top[m.active] = 0, 0
	case tea.KeyEsc:
		m.searching = false
		m.input = m.filter[m.active]
	case tea.KeyBackspace:
		if r := []rune(m.input); len(r) > 0 {
			m.input = string(r[:len(r)-1])
		}
	case tea.KeyRunes, tea.KeySpace:
		if len([]rune(m.input)) < 80 {
			m.input += string(k.Runes)
			if k.Type == tea.KeySpace {
				m.input += " "
			}
		}
	}
}

func (m *Model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "q", "ctrl+c":
		m.Quit = true
		return m, tea.Quit
	case "?":
		m.showHelp = !m.showHelp
	case "tab", "right", "l":
		m.switchTab((m.active + 1) % len(m.tabs))
	case "shift+tab", "left", "h":
		m.switchTab((m.active + len(m.tabs) - 1) % len(m.tabs))
	case "1", "2", "3", "4", "5", "6":
		m.switchTab(int(k.String()[0] - '1'))
	case "down", "j":
		m.cursor[m.active]++
	case "up", "k":
		m.cursor[m.active]--
	case "pgdown", "ctrl+d":
		m.cursor[m.active] += max(m.listHeight()-1, 1)
	case "pgup", "ctrl+u":
		m.cursor[m.active] -= max(m.listHeight()-1, 1)
	case "g", "home":
		m.cursor[m.active] = 0
	case "G", "end":
		m.cursor[m.active] = 1 << 30
	case "/":
		m.searching, m.input = true, m.filter[m.active]
	case "esc":
		m.showHelp = false
		if m.filter[m.active] != "" {
			m.filter[m.active], m.input = "", ""
		} else {
			m.pin[m.active], m.pinned[m.active] = nil, ""
		}
		m.cursor[m.active], m.top[m.active] = 0, 0
	case "e":
		m.jumpToEvidence()
	case "f":
		m.jumpToFindings()
	}
	m.clamp()
	return m, nil
}

func (m *Model) switchTab(i int) {
	if i >= 0 && i < len(m.tabs) {
		m.active = i
		m.input = m.filter[i]
		m.clamp()
	}
}

func (m *Model) tabIndex(name string) int {
	for i, t := range m.tabs {
		if t.name == name {
			return i
		}
	}
	return -1
}

func (m *Model) selected() (row, bool) {
	rows := m.visible(m.active)
	if len(rows) == 0 {
		return row{}, false
	}
	return rows[max(0, min(m.cursor[m.active], len(rows)-1))], true
}

// jumpToEvidence opens the Evidence tab restricted to what the selected
// finding or capability cites.
func (m *Model) jumpToEvidence() {
	r, ok := m.selected()
	dst := m.tabIndex("Evidence")
	if !ok || dst < 0 || len(r.evidence) == 0 {
		return
	}
	set := map[string]bool{}
	for _, id := range r.evidence {
		set[id] = true
	}
	m.pin[dst], m.pinned[dst] = set, "evidence cited by "+r.key
	m.filter[dst], m.cursor[dst], m.top[dst] = "", 0, 0
	m.switchTab(dst)
}

// jumpToFindings opens the Findings tab restricted to findings that cite the
// selected evidence.
func (m *Model) jumpToFindings() {
	r, ok := m.selected()
	dst := m.tabIndex("Findings")
	if !ok || dst < 0 || len(r.findings) == 0 {
		return
	}
	set := map[string]bool{}
	for _, id := range r.findings {
		set[id] = true
	}
	m.pin[dst], m.pinned[dst] = set, "findings citing "+r.key
	m.filter[dst], m.cursor[dst], m.top[dst] = "", 0, 0
	m.switchTab(dst)
}

// ---- rendering

func (m *Model) style(base lipgloss.Style) lipgloss.Style {
	if !m.color {
		return lipgloss.NewStyle()
	}
	return base
}

func clipTo(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return "…"
	}
	return string(r[:w-1]) + "…"
}

func wrap(s string, w int) []string {
	if w < 8 {
		w = 8
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			for len([]rune(word)) > w {
				if line != "" {
					out = append(out, line)
					line = ""
				}
				r := []rune(word)
				out = append(out, string(r[:w]))
				word = string(r[w:])
			}
			switch {
			case line == "":
				line = word
			case len([]rune(line))+1+len([]rune(word)) <= w:
				line += " " + word
			default:
				out = append(out, line)
				line = word
			}
		}
		out = append(out, line)
	}
	return out
}

// View implements tea.Model.
func (m *Model) View() string {
	m.clamp()
	var b strings.Builder
	bold := m.style(lipgloss.NewStyle().Bold(true))
	dim := m.style(lipgloss.NewStyle().Faint(true))
	sel := m.style(lipgloss.NewStyle().Reverse(true))
	on := m.style(lipgloss.NewStyle().Bold(true).Underline(true))

	head := fmt.Sprintf("UNPACKR inspect  %s", m.r.File.Name)
	if a := m.r.Analysis; a != nil {
		head += "  |  packing: " + a.Packing.State
	}
	b.WriteString(bold.Render(clipTo(head, m.w)) + "\n")
	b.WriteString(dim.Render(clipTo("sha256 "+m.r.File.Hashes.SHA256, m.w)) + "\n")

	var tabs []string
	for i, t := range m.tabs {
		label := fmt.Sprintf("%d %s", i+1, t.name)
		if n := len(m.visible(i)); n != len(t.rows) || m.pin[i] != nil {
			label += fmt.Sprintf(" (%d/%d)", n, len(t.rows))
		} else {
			label += fmt.Sprintf(" (%d)", len(t.rows))
		}
		if i == m.active {
			label = on.Render("[" + label + "]")
		} else {
			label = " " + label + " "
		}
		tabs = append(tabs, label)
	}
	b.WriteString(clipTo(strings.Join(tabs, " "), m.w+200) + "\n\n")

	if m.showHelp {
		b.WriteString(helpText())
		return b.String()
	}

	rows := m.visible(m.active)
	lh := m.listHeight()
	if len(rows) == 0 {
		msg := "nothing in this tab"
		if m.filter[m.active] != "" || m.pin[m.active] != nil {
			msg = "no rows match; press esc to clear the filter"
		}
		b.WriteString(dim.Render(msg) + "\n")
	}
	end := min(len(rows), m.top[m.active]+lh)
	for i := m.top[m.active]; i < end; i++ {
		line := clipTo(rows[i].line, m.w-2)
		if i == m.cursor[m.active] {
			b.WriteString(sel.Render("> "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	for i := end - m.top[m.active]; i < lh; i++ {
		b.WriteString("\n")
	}
	b.WriteString(dim.Render(strings.Repeat("─", max(m.w, 1))) + "\n")

	if r, ok := m.selected(); ok {
		dh := m.h - 6 - lh - 1
		lines := wrap(r.detail, m.w-1)
		for i := 0; i < len(lines) && i < max(dh, 1); i++ {
			b.WriteString(lines[i] + "\n")
		}
		if len(lines) > max(dh, 1) {
			b.WriteString(dim.Render(fmt.Sprintf("… %d more line(s); enlarge the window to see them", len(lines)-max(dh, 1))) + "\n")
		}
	}

	status := "q quit  ? help  / search  tab next  e evidence  f findings"
	switch {
	case m.searching:
		status = "search: " + m.input + "▏  (enter apply, esc cancel)"
	case m.pin[m.active] != nil:
		status = "showing " + m.pinned[m.active] + "  (esc to clear)"
	case m.filter[m.active] != "":
		status = fmt.Sprintf("filter %q  (esc to clear)", m.filter[m.active])
	}
	b.WriteString(dim.Render(clipTo(status, m.w)) + "\n")
	return b.String()
}

func helpText() string {
	return `Keys
  tab / shift+tab, left / right, 1-6   switch tab
  up / down, j / k                      move
  pgup / pgdn, g / G                    page, top, bottom
  /                                     search the current tab (case-insensitive)
  esc                                   clear search or evidence filter, close help
  e                                     from a finding or capability: open the evidence it cites
  f                                     from an evidence row: open the findings that cite it
  q                                     quit

What you see
  Everything here is read from the report. Nothing was executed. Control and
  escape bytes in sample strings are shown as visible escapes, never sent to
  your terminal. Confidence is ordinal, not a probability.
`
}

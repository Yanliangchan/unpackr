package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/Yanliangchan/unpackr/pkg/models"
)

// Run shows an already-sanitised report and blocks until the user quits.
//
// Importing this package links Bubble Tea, whose package initialiser probes
// the terminal for its background colour. That is why Run lives behind the
// separate unpackr-inspect executable: the main binary must not import this
// package (a boundary test enforces it), or every invocation would probe.
func Run(r *models.Report, color bool) error {
	// The view uses only bold, faint, reverse and underline, which do not
	// depend on the terminal background.
	if color {
		lipgloss.SetColorProfile(termenv.ANSI)
	} else {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	lipgloss.SetHasDarkBackground(true)
	_, err := tea.NewProgram(New(r, Options{Color: color}), tea.WithAltScreen()).Run()
	return err
}

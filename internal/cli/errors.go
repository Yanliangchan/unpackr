package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

// Exit codes.
const (
	ExitOK             = 0
	ExitAnalysisError  = 1
	ExitUsage          = 2
	ExitNotImplemented = 4
)

// UsageError is a bad combination or value of command-line arguments.
type UsageError struct{ Msg string }

func (e *UsageError) Error() string { return e.Msg }

func usagef(format string, a ...any) error { return &UsageError{Msg: fmt.Sprintf(format, a...)} }

// NotImplementedError means the option is valid but this build does not
// provide it. The tool refuses rather than pretending.
type NotImplementedError struct{ Feature string }

func (e *NotImplementedError) Error() string {
	return e.Feature + " is not implemented in this build"
}

// ExitCode maps an error to a process exit code.
func ExitCode(err error) int {
	var u *UsageError
	var n *NotImplementedError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &u):
		return ExitUsage
	case errors.As(err, &n):
		return ExitNotImplemented
	default:
		return ExitAnalysisError
	}
}

// usageArgs makes argument-count errors from cobra count as usage errors.
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, a []string) error {
		if err := v(c, a); err != nil {
			return &UsageError{Msg: err.Error()}
		}
		return nil
	}
}

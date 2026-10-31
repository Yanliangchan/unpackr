//go:build linux && amd64

package safety

func deniedSyscalls() []string { return append(append([]string{}, commonDenied...), "fork", "vfork") }

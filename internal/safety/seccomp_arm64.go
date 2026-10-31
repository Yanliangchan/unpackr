//go:build linux && arm64

package safety

// arm64 has no fork/vfork syscalls. This build has been cross-compiled but not
// yet exercised on arm64 hardware.
func deniedSyscalls() []string { return append([]string{}, commonDenied...) }

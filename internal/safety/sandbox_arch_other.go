//go:build linux && !amd64 && !arm64

package safety

func deniedSyscalls() []string { return append([]string{}, commonDenied...) }

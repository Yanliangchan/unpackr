//go:build !linux

package safety

import "github.com/Yanliangchan/unpackr/pkg/models"

// ApplySandbox is unavailable off Linux; the status says so.
func ApplySandbox(SandboxOptions) models.SandboxStatus {
	return models.SandboxStatus{Level: LevelNone, Detail: "sandbox is only implemented on Linux"}
}

// Describe is used in diagnostics.
func Describe(s models.SandboxStatus) string { return s.Level }

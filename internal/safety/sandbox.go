package safety

import "github.com/Yanliangchan/unpackr/pkg/models"

// SandboxOptions controls the confinement a worker applies to itself before it
// touches any untrusted data.
type SandboxOptions struct {
	// MemoryLimitBytes caps the address space (RLIMIT_AS). 0 disables it.
	MemoryLimitBytes uint64
	// MaxFileSizeBytes caps files the worker may create (RLIMIT_FSIZE).
	MaxFileSizeBytes uint64
	// WritableDirs may be written; ReadableDirs may be read. Everything else
	// on the filesystem is denied. Both are normally empty: input arrives as
	// an inherited file descriptor.
	WritableDirs []string
	ReadableDirs []string
}

// Level names the overall result.
const (
	LevelFull    = "full"
	LevelPartial = "partial"
	LevelNone    = "none"
)

func finishStatus(s *models.SandboxStatus) {
	switch {
	case s.NoNewPrivs && s.Landlock && s.Seccomp && s.MemoryLimit:
		s.Level = LevelFull
	case s.NoNewPrivs || s.Landlock || s.Seccomp:
		s.Level = LevelPartial
	default:
		s.Level = LevelNone
	}
}

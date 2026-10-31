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

	// AllowExec lets the process call execve once, to start an external
	// tool. Landlock then limits what may be executed to ExecFiles, so the
	// tool cannot start anything else. Used only by the exec worker.
	AllowExec bool
	// ExecFiles may be read and executed (the tool and its dynamic loader).
	ExecFiles []string
	// ReadOnlyNoExec may be read but never executed (shared libraries).
	ReadOnlyNoExec []string
	// ReadFiles may be read (single files, such as the loader cache).
	ReadFiles []string
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

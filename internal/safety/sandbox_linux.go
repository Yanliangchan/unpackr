//go:build linux

package safety

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/Yanliangchan/unpackr/pkg/models"
	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/landlock-lsm/go-landlock/landlock"
	llsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// landlockABI returns the kernel's Landlock ABI version, or 0 if unavailable.
func landlockABI() int {
	v, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, 1) // LANDLOCK_CREATE_RULESET_VERSION
	if errno != 0 {
		return 0
	}
	return int(v)
}

// ApplySandbox confines the calling process. It is irreversible and must be
// called by a worker before any untrusted input is read. It never returns an
// error for a missing kernel feature: it reports exactly what was achieved so
// callers can fail closed when they require full confinement.
func ApplySandbox(o SandboxOptions) models.SandboxStatus {
	var st models.SandboxStatus
	var notes []string

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err == nil {
		st.NoNewPrivs = true
	} else {
		notes = append(notes, "no_new_privs: "+err.Error())
	}

	if o.MemoryLimitBytes > 0 {
		l := &unix.Rlimit{Cur: o.MemoryLimitBytes, Max: o.MemoryLimitBytes}
		if err := unix.Setrlimit(unix.RLIMIT_AS, l); err == nil {
			st.MemoryLimit = true
		} else {
			notes = append(notes, "rlimit_as: "+err.Error())
		}
	}
	if o.MaxFileSizeBytes > 0 {
		l := &unix.Rlimit{Cur: o.MaxFileSizeBytes, Max: o.MaxFileSizeBytes}
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, l); err != nil {
			notes = append(notes, "rlimit_fsize: "+err.Error())
		}
	}
	// Core dumps of a worker holding sample bytes are never wanted.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})

	st.LandlockABI = landlockABI()
	if st.LandlockABI > 0 {
		var rules []landlock.Rule
		if len(o.ReadableDirs) > 0 {
			rules = append(rules, landlock.RODirs(o.ReadableDirs...))
		}
		if len(o.WritableDirs) > 0 {
			rules = append(rules, landlock.RWDirs(o.WritableDirs...))
		}
		if len(o.ExecFiles) > 0 {
			rules = append(rules, landlock.ROFiles(o.ExecFiles...))
		}
		if len(o.ReadFiles) > 0 {
			rules = append(rules, landlock.PathAccess(landlock.AccessFSSet(llsyscall.AccessFSReadFile), o.ReadFiles...))
		}
		if len(o.ReadOnlyNoExec) > 0 {
			rules = append(rules, landlock.PathAccess(landlock.AccessFSSet(llsyscall.AccessFSReadFile|llsyscall.AccessFSReadDir), o.ReadOnlyNoExec...))
		}
		if err := landlock.V5.BestEffort().RestrictPaths(rules...); err == nil {
			st.Landlock = true
		} else {
			notes = append(notes, "landlock fs: "+err.Error())
		}
		if st.Landlock && st.LandlockABI >= 4 {
			if err := landlock.V5.BestEffort().RestrictNet(); err == nil {
				st.LandlockNet = true
			} else {
				notes = append(notes, "landlock net: "+err.Error())
			}
		}
	} else {
		notes = append(notes, "landlock unavailable on this kernel")
	}

	f := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls:      []seccomp.SyscallGroup{{Action: seccomp.ActionErrno, Names: filterExec(deniedSyscalls(), o.AllowExec)}},
		},
	}
	if err := seccomp.LoadFilter(f); err == nil {
		st.Seccomp = true
	} else {
		notes = append(notes, "seccomp: "+err.Error())
	}

	st.Detail = strings.Join(notes, "; ")
	finishStatus(&st)
	return st
}

// commonDenied are syscalls a parser or extractor worker never needs. Thread
// creation (clone) and memory management are deliberately allowed because the
// Go runtime needs them.
var commonDenied = []string{
	"socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
	"execve", "execveat", "ptrace", "process_vm_readv", "process_vm_writev",
	"mount", "umount2", "pivot_root", "chroot", "unshare", "setns",
	"kexec_load", "init_module", "finit_module", "delete_module",
	"bpf", "perf_event_open", "keyctl", "add_key", "request_key",
}

// Describe is used in diagnostics.
func Describe(s models.SandboxStatus) string {
	return fmt.Sprintf("%s (no_new_privs=%t landlock=%t abi=%d net=%t seccomp=%t memlimit=%t)",
		s.Level, s.NoNewPrivs, s.Landlock, s.LandlockABI, s.LandlockNet, s.Seccomp, s.MemoryLimit)
}

// filterExec removes execve/execveat from the deny list when one exec is
// allowed.
func filterExec(names []string, allow bool) []string {
	if !allow {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n != "execve" && n != "execveat" {
			out = append(out, n)
		}
	}
	return out
}

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/elastic/go-seccomp-bpf"
	"github.com/landlock-lsm/go-landlock/landlock"
	"golang.org/x/sys/unix"
)

func worker() {
	// no_new_privs + rlimits
	unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	unix.Setrlimit(unix.RLIMIT_AS, &unix.Rlimit{Cur: 2 << 30, Max: 2 << 30})
	unix.Setrlimit(unix.RLIMIT_NPROC, &unix.Rlimit{Cur: 0, Max: 0})
	// Landlock: read-only access to input dir, rw to scratch, nothing else; network denied (ABI4+)
	err := landlock.V5.BestEffort().RestrictPaths(
		landlock.RODirs(os.Args[2], "/lib", "/usr/lib", "/lib64"),
		landlock.RWDirs(os.Args[3]),
	)
	fmt.Println("landlock fs err:", err)
	err = landlock.V5.BestEffort().RestrictNet() // no bind/connect rules => all TCP denied
	fmt.Println("landlock net err:", err)
	// seccomp: deny process creation, sockets, ptrace
	f := seccomp.Filter{
		NoNewPrivs: true, Flag: seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{DefaultAction: seccomp.ActionAllow, Syscalls: []seccomp.SyscallGroup{{
			Action: seccomp.ActionErrno, Names: []string{"socket", "connect", "execve", "execveat", "ptrace", "fork", "vfork", "mount", "unshare", "setns"},
		}}},
	}
	fmt.Println("seccomp load err:", seccomp.LoadFilter(f))
	_, e := os.ReadFile(os.Args[2] + "/in.bin")
	fmt.Println("read input:", e)
	_, e = os.ReadFile("/etc/passwd")
	fmt.Println("read /etc/passwd:", e)
	e = os.WriteFile(os.Args[2]+"/x", []byte("x"), 0600)
	fmt.Println("write into input dir:", e)
	e = os.WriteFile(os.Args[3]+"/ok", []byte("x"), 0600)
	fmt.Println("write scratch:", e)
	_, e = net.Dial("tcp", "1.1.1.1:80")
	fmt.Println("net dial:", e)
	e = exec.Command("/bin/true").Run()
	fmt.Println("exec:", e)
	_, _, en := syscall.Syscall(syscall.SYS_SOCKET, 2, 1, 0)
	fmt.Println("raw socket errno:", en)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--worker" {
		worker()
		return
	}
	os.MkdirAll("/tmp/spike/sbx_in", 0755)
	os.MkdirAll("/tmp/spike/sbx_out", 0755)
	os.WriteFile("/tmp/spike/sbx_in/in.bin", []byte("data"), 0644)
	c := exec.Command(os.Args[0], "--worker", "/tmp/spike/sbx_in", "/tmp/spike/sbx_out")
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	fmt.Println("run:", c.Run())
}

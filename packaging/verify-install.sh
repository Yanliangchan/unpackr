#!/usr/bin/env bash
# Verify that the .deb installs and works on a clean system. Run as root inside a
# fresh container with the package directory mounted at /dist (read-only).
#   docker run --rm -v "$PWD/dist:/dist:ro" -v "$PWD/packaging/verify-install.sh:/verify.sh:ro" kalilinux/kali-rolling bash /verify.sh
set -uo pipefail
fail=0
ok()  { printf 'ok    %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
check() { local what=$1; shift; if "$@" >/tmp/out 2>&1; then ok "$what"; else bad "$what"; sed 's/^/        /' /tmp/out | head -8; fi; }

. /etc/os-release
echo "== $PRETTY_NAME on $(dpkg --print-architecture) =="

export DEBIAN_FRONTEND=noninteractive
# Minimised container images tell dpkg not to install man pages and docs. That
# is a property of the image, not of the package, and would hide whether the
# package ships them, so it is lifted for this test.
rm -f /etc/dpkg/dpkg.cfg.d/excludes /etc/dpkg/dpkg.cfg.d/docker
apt-get update -qq >/dev/null 2>&1 || bad "apt-get update"
deb=$(ls /dist/unpackr_*_"$(dpkg --print-architecture)".deb 2>/dev/null | head -n1)
[ -n "$deb" ] || { echo "no .deb for $(dpkg --print-architecture) in /dist"; exit 1; }
check "checksum matches SHA256SUMS" bash -c "cd /dist && grep ' $(basename "$deb")\$' SHA256SUMS | sha256sum -c -"

# Nothing else is installed first: the package declares no dependencies.
check "installs with apt and no other packages" apt-get install -y -qq --no-install-recommends "$deb"
check "package is registered" dpkg -s unpackr
check "unpackr is in PATH" command -v unpackr
check "unpackr-inspect is next to it" test -x "$(dirname "$(command -v unpackr)")/unpackr-inspect"

check "binary is statically linked (no shared libraries needed)" bash -c '! ldd "$(command -v unpackr)" 2>&1 | grep -v "not a dynamic executable\|statically linked" | grep -q "=>"'
check "--version names the right architecture" bash -c "unpackr --version | grep -q \"$(dpkg --print-architecture | sed 's/amd64/amd64/;s/arm64/arm64/')\""
check "doctor runs" unpackr doctor
echo "---- doctor ----"; unpackr doctor 2>&1 | sed 's/^/    /' | head -30; echo "----------------"

# Analyse a real executable of this system, in every profile.
check "info analysis of /bin/ls" bash -c 'unpackr --no-banner --no-db --format json /bin/ls | grep -q "\"schema_version\""'
check "quick analysis" bash -c 'unpackr --no-banner --no-db -q /bin/ls >/dev/null'
check "deep analysis" bash -c 'unpackr --no-banner --no-db -d /bin/ls | grep -q "Code "'
check "html report is written" bash -c 'cd /tmp && unpackr --no-banner --no-db /bin/ls -o r.html && grep -q "<html" r.html'
check "inspect refuses without a terminal, politely" bash -c 'unpackr inspect /bin/ls </dev/null 2>&1 | grep -q "interactive terminal"'
check "yara suggest runs and states what it could not test" bash -c 'unpackr --no-banner yara suggest /bin/ls 2>&1 | grep -q -e "NOT compiled or tested" -e "compiles with" -e "No rule drafted"'

# The sandbox must be reported honestly, not assumed.
check "sandbox status is stated" bash -c 'unpackr doctor 2>&1 | grep -qi sandbox'

# Documentation and completions.
check "man page file is installed" test -f /usr/share/man/man1/unpackr.1.gz
check "man page is valid roff" bash -c 'zcat /usr/share/man/man1/unpackr.1.gz | grep -q "^.TH UNPACKR"'
check "bash completion installed" test -s /usr/share/bash-completion/completions/unpackr
check "zsh completion installed" test -s /usr/share/zsh/vendor-completions/_unpackr
check "fish completion installed" test -s /usr/share/fish/vendor_completions.d/unpackr.fish
check "licence and notices installed" bash -c 'test -s /usr/share/doc/unpackr/copyright && test -s /usr/share/doc/unpackr/THIRD-PARTY.md'
check "bash completion loads" bash -c 'apt-get install -y -qq bash-completion >/dev/null 2>&1; bash -c "source /usr/share/bash-completion/completions/unpackr && complete -p unpackr >/dev/null"'
# man itself is a stub in minimised container images, so the page is checked
# with mandoc, which also lints the roff source.
if apt-get install -y -qq --no-install-recommends mandoc >/dev/null 2>&1; then
  check "man page has no roff errors" bash -c 'zcat /usr/share/man/man1/unpackr.1.gz > /tmp/unpackr.1 && ! mandoc -T lint -W error /tmp/unpackr.1 2>&1 | grep -q .'
  check "man page renders with the expected sections" bash -c 'mandoc -T ascii /tmp/unpackr.1 | sed "s/.\\x08//g" > /tmp/page.txt && grep -q "^NAME" /tmp/page.txt && grep -q "^EXIT STATUS" /tmp/page.txt && grep -q -e "--deep" /tmp/page.txt'
else
  echo "skip  mandoc could not be installed"
fi

# Removal leaves nothing behind.
check "removal succeeds" apt-get remove -y -qq unpackr
check "removal deletes the binaries" bash -c '! test -e /usr/bin/unpackr && ! test -e /usr/bin/unpackr-inspect && ! test -e /usr/share/man/man1/unpackr.1.gz'

if [ "$fail" -eq 0 ]; then echo "== all checks passed =="; else echo "== FAILURES =="; fi
exit "$fail"

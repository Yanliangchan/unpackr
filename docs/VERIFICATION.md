# UNPACKR — Upstream Verification Report

Scope: confirm the `[V]` items in `ARCHITECTURE.md` before any product code.
Date of verification: 2026-10-31. Environment: Ubuntu 24.04 container, kernel
6.18, 4 cores, Go 1.24.7 (auto-upgraded to 1.26 by some dependencies), Python
3.13, Rust toolchain present.

## 1. What was and was not verified

| Method | Reach | Used for |
|---|---|---|
| Go module proxy | all Go modules | latest version, release date, source |
| PyPI JSON API | all PyPI packages | version, last upload, declared licence |
| `raw.githubusercontent.com` | licence files, manifests, source files | licence text, `Cargo.toml`, `version.h` |
| crates.io index/static | Rust crates | built `yara-x-cli` from source |
| Debian/Ubuntu apt mirror | packaged tools | distro versions of UPX, p7zip, bubblewrap |
| Hands-on tests in this container | | parsers, YARA-X, sandbox, SQLite, UPX, FLOSS |

**Not reachable from this environment:** `github.com` (releases, archives),
the GitHub API, Kali mirrors. Therefore **no hands-on testing was possible for
Ghidra, Rizin, radare2, Detect It Easy, ILSpy, de4dot, Binary Ninja, RetDec,
capa-rules, or unblob extraction behaviour**, and release dates for non-Go,
non-Python projects are unconfirmed. Section 7 lists these as outstanding and
`spikes/verify-tools.sh` (to be run on a real Kali host) closes them. They are
not being treated as verified.

## 2. Parser verification (decisions D2, D7)

### 2.1 Robustness under hostile input

Method: for each fixture (Go-built PE amd64/arm64, UPX-packed PE, ELF amd64/arm64,
UPX-packed ELF, Mach-O amd64/arm64) apply 1–16 random byte changes in the first
4 KiB, truncate one case in six, run the parser inside a recover/5-second
watchdog. Same seed. Source: `spikes/goprobe`, `spikes/pyprobe.py`.

PE, 900 mutated inputs (3 fixtures × 300):

| Parser | parsed | rejected | panics | hangs | total time |
|---|---|---|---|---|---|
| `saferwall/pe` v1.6.5 (Go) | 869 | 31 | 0 | 0 | ~17 s (all formats combined run) |
| Go `debug/pe` | 429 | 452 | **19** | 0 | — |
| pefile 2024.8.26 (Python) | 876 | 24 | 0 exceptions | — | 269 s |
| LIEF 1.0.0 (C++/Python) | 876 | 24 | 0 | — | 90 s |

Other formats (2400 mutated inputs across 8 fixtures):

| Parser | parsed | rejected | panics | hangs |
|---|---|---|---|---|
| Go `debug/elf` | 592 | 308 | 0 | 0 |
| Go `debug/macho` | 350 | 250 | 0 | 0 |
| `blacktop/go-macho` v1.1.296 | 337 | 262 | 0 | **1** |

Conclusions:
- Go `debug/pe` is **not acceptable** for hostile input: 2% of mutated files crash it.
- `saferwall/pe` is as tolerant as pefile and LIEF (within 7 files of 900), with
  no panics in this run. This is a small sample, not proof; it must be fuzzed.
- `go-macho` **hung once**. A goroutine cannot be killed in Go. Any parser that
  can loop must run in a killable process. It also prints diagnostics to the
  standard logger on unknown load commands, which must be silenced.

### 2.2 Accuracy on clean files (Go-built PE and UPX-packed PE)

| Field | saferwall/pe | pefile | LIEF |
|---|---|---|---|
| Sections (names, virtual/raw size, flags) | identical | identical | not compared field-by-field |
| Entry point | `0x77280` / `0x857b00` | same | same |
| Import count | 46 / 4 | 46 / 4 | 46 / 4 |
| **Import hash** | `d42595b6…` / `6ed4f5f0…` | `d42595b6…` / `6ed4f5f0…` | **`e06cb21f…` / `e994338d…`** |
| Parse time (8 MB file) | **8.7 ms** | 281 ms | 14 ms |

- saferwall/pe matches pefile exactly, including imphash.
- **LIEF's imphash differs from the pefile/industry-standard imphash.** LIEF must
  never be the source of import hashes, and the cross-check worker must normalise
  or skip that field.
- Differences were also seen on COFF symbol handling in pefile for UPX files (a
  `Failed to parse COFF symbol` message from LIEF); anomaly reporting differs
  between engines, which is exactly what the disagreement finding is for.

### 2.3 Verdicts

- **D7 confirmed**, with a stronger rationale than before: `saferwall/pe` is MIT,
  actively released (v1.6.5, 2026-05-23), fast, and pefile-equivalent on tested
  inputs. Use as base; pefile and LIEF as oracles.
- **D2 confirmed, with a constraint:** go-macho (MIT, release 2026-10-31, very
  active) is the base, but must be fuzzed and run killable.
- **ELF:** `debug/elf` survived the mutation test but requires section headers
  for several accessors, so the program-header-only fallback remains necessary.
  `saferwall/elf` is stale (2024-06) and rejected.

## 3. Rule engine verification (decision D1)

- YARA-X 1.22.1 (2026-10-26), BSD-3-Clause (checked in `Cargo.toml` and
  `LICENSE`). `cargo install yara-x-cli` builds the `yr` binary from crates.io.
- `yr` binary: 42.5 MB unstripped; dynamically links only libc, libm, libgcc.
- Scan of a 30-byte rule against a 4.7 MB file through the CLI: **11 ms wall**
  including process start.
- Library timings (Python binding, same engine): compile 5 000 rules 0.31 s;
  scan 8 MB with 5 000 rules 10 ms.
- `pe.sections`, `pe.number_of_imports`, `elf.sections` modules worked: UPX0/UPX1
  section detection, Go-PE heuristic, Go ELF `.gopclntab` all matched correctly
  on the right fixtures and nowhere else. (One UPX-packed Go ELF still matched a
  `Go buildinf` string rule — evidence that string rules on packed files need
  structure conditions.)
- Compiled-rule cache (`yr compile`) works (69 KB for 1 rule file).
- `hillu/go-yara` (libyara via cgo, BSD, v4.3.4, 2025-07) is stale relative to
  YARA-X and requires cgo: rejected.
- **Verdict:** D1 confirmed. Subprocess `yr` is fast enough that an in-process
  binding is unnecessary.

### Rule corpus licences (new finding)

| Corpus | Licence | Consequence |
|---|---|---|
| Yara-Rules/rules | GPL-2.0 | Cannot be merged into an Apache-2.0 rule pack; ship as separate, user-installed pack |
| Neo23x0/signature-base | Detection Rule License 1.1 | Attribution/terms; separate pack |
| Elastic protections-artifacts | Elastic License 2.0 | Not open source; do not redistribute inside the `.deb` |
| ReversingLabs YARA rules | MIT | Bundlable |
| mandiant/capa-rules | Apache-2.0 | Bundlable |

Rule packs therefore carry per-pack licence metadata, and the default pack only
contains rules we can redistribute.

## 4. Integration tool verification (D6, D8, D9)

| Tool | Version found | Last release | Licence | Notes |
|---|---|---|---|---|
| UPX | upstream 5.3.1 (`version.h`); distro package **4.2.2** | upstream active | GPL-2.0+ with stub exception | Distro lags a major release. Bundle must be built from verified upstream source |
| p7zip (distro) | **16.02** | very old | LGPL + unRAR | Do not use the distro package; use upstream 7-Zip (`7zz`) or avoid |
| bubblewrap | distro package (version not recorded) | — | LGPL | Works here; see section 6 caveat |
| capa (`flare-capa`) | 10.0.0 | 2026-10-16 | Apache-2.0 | Installs and runs (`--version`); rules fetched separately; capa-rules is Apache-2.0 |
| FLOSS (`flare-floss`) | 3.2.0 | 2026-10-21 | Apache-2.0 | Static-string mode ran in 2.6 s on an 8 MB PE |
| LIEF | 1.0.0 | 2026-07-12 | Apache-2.0 | Fast, active |
| pefile | 2024.8.26 | **2024-08-26** | MIT | No release in 26 months; fine as a frozen oracle |
| YARA-X | 1.22.1 | 2026-10-26 | BSD-3 | Active, rapid cadence |
| unblob | 26.6.4 | 2026-06-04 | MIT | Active; extraction behaviour not tested here |
| dnfile | 0.18.0 | 2026-01-31 | MIT | Reference for .NET metadata tests |
| speakeasy | 1.5.11 | 2026-10-11 | MIT | Active; Windows user/kernel-mode emulator |
| Qiling | 1.4.6 | **2023-08-04** | GPL-2 | Unmaintained: dropped from the emulation plan |
| unipacker | 1.0.8 | 2024-05-21 | GPL-2 | Stale: not a dependency |
| vivisect (FLOSS/capa emulation backend) | 1.3.2 | 2026-03-31 | Apache-2.0 | Maintained |
| binary-refinery | 0.11.3 | 2026-10-26 | (undeclared on PyPI) `[V]` | Active; confirm licence |
| pyinstxtractor-ng | 2026.7.3 | 2026-07-03 | GPL-3.0 | Maintained; native CArchive reader still preferred |
| pycdc (GitHub) | — | `[V]` | GPL (repo text) | PyPI project named `pycdc` is MIT and may be unrelated: confirm |
| uncompyle6 / decompyle3 | 3.9.3 | 2025-09/10 | GPL-3 | Limited to older Python versions `[V]` |
| angr | 10.0.5 | 2026-10-22 | BSD-2 | Heavy; optional CFG/symbolic backend only |
| pyghidra | 3.2.0 | 2026-10-22 | Apache-2.0 | Official Ghidra Python bridge: enables the Ghidra adapter without hand-built headless scripts |
| Capstone | 5.0.9 | 2026-09-21 | BSD | Active |
| radare2 / r2pipe | r2pipe 2.1.0 (2026-10-19) | active | LGPL/GPL `[V]` | |
| Rizin | — | `[V]` | GPL-3.0 (COPYING) | rz-ghidra is LGPL-3.0 |
| Ghidra | — | `[V]` | Apache-2.0 | |
| Detect It Easy | — | `[V]` | MIT (repo LICENSE) | `diec` console exists per README |
| ILSpy | — | `[V]` | MIT | |
| RetDec | — | `[V]` | MIT (repo LICENSE) | Maintenance status unknown |
| Binary Ninja API | — | `[V]` | MIT (API repo only; product is commercial) | |
| IDA Free | — | — | proprietary | No headless automation: unsupported (unchanged) |

Go libraries:

| Module | Version | Date | Licence | Verdict |
|---|---|---|---|---|
| saferwall/pe | v1.6.5 | 2026-05-23 | MIT | adopt |
| blacktop/go-macho | v1.1.296 | 2026-10-31 | MIT | adopt, killable |
| glaslos/ssdeep | v1.0.0 | 2026-04-06 | MIT | adopt for interoperability; validate against libfuzzy on a corpus |
| glaslos/tlsh | v0.4.0 | 2025-08-12 | Apache-2.0 | adopt; validate against reference TLSH |
| modernc.org/sqlite | v1.61.1 | 2026-10-31 | BSD-3 | **adopt** |
| ncruces/go-sqlite3 | v0.36.0 | 2026-10-29 | MIT | rejected (below) |
| landlock-lsm/go-landlock | v0.11.0 | 2026-10-23 | MIT | adopt |
| elastic/go-seccomp-bpf | v1.6.0 | 2025-06-20 | Apache-2.0 | adopt (activity moderate; the filter is small enough to vendor) |
| charmbracelet/bubbletea | v1.3.10 | 2025-09-17 | MIT | adopt; v2 line to be checked at start |
| spf13/cobra | v1.10.2 | 2025-12-03 | Apache-2.0 | adopt |

## 5. Storage verification (D5)

300 000 inserts in one transaction, 20 000 indexed lookups, WAL, single
connection (`spikes/dbbench`):

| Driver | insert | lookups | FTS5 | Notes |
|---|---|---|---|---|
| modernc.org/sqlite | 1.03 s | 156 ms | **yes** | pure Go, no cgo |
| ncruces/go-sqlite3 | 0.98 s | 159 ms | **no in the default build** | pulled in a Go 1.26 toolchain |

No performance difference. FTS5 is required for analyst notes and string search.
**modernc.org/sqlite wins.**

## 6. Sandbox verification (security model)

- `bwrap --unshare-all` worked in this container and blocked the network
  (HTTP code `000`). **But** it needs unprivileged user namespaces. Ubuntu 24.04
  restricts these by default through AppArmor for unconfined programs, and
  hardened Kali/Debian setups may disable them. The container here runs as root,
  which hides the problem. Therefore bubblewrap cannot be the primary sandbox.
- **Self-sandboxing worker without user namespaces works.** A re-executed Go
  worker applying Landlock (ABI 7 available on this 6.18 kernel), seccomp-bpf,
  `no_new_privs` and rlimits (`spikes/sbx`) produced:
  - read of the input directory: allowed
  - read of `/etc/passwd`: denied
  - write into the input directory: denied
  - write into the scratch directory: allowed
  - TCP connect: denied (`socket: operation not permitted`)
  - `execve`: denied
  - raw `socket` syscall: denied
- This is a single-kernel result. The design needs a capability matrix per
  kernel (Landlock ABI, seccomp availability) with `--require-sandbox` failing
  closed and `doctor` reporting the achieved level.

## 7. Packer and unpacker findings

- UPX unpack round trip (distro 4.2.2 packing then unpacking a Go PE): output
  is **the same size but not byte-identical** (18 bytes differ: PE header area
  and a tail region). SHA-256 differs. Unpack validation therefore must be
  structural (re-parse, section and import sanity, entry point in code), never
  "hash equals original". The original-hash expectation must not appear anywhere.
- UPX packed the Go PE to 57% of original size; the packed fixtures were
  correctly flagged by YARA-X (`UPX0`/`UPX1` section names).

## 8. Outstanding verification (must run on a real Kali host)

Items that could not be checked here and will be closed by `spikes/verify-tools.sh`
before the corresponding adapter is built: Ghidra (version, PyGhidra headless
run, memory use, time on the fixtures), Rizin (Kali package version, `rz-bin -j`
output stability, rz-ghidra availability), Detect It Easy (`diec` JSON output),
ILSpy (`ilspycmd` on Kali, .NET runtime requirement), capa-rules checkout and a
capa run, unblob extraction on the fixtures, UPX 5.x build, 7zz build, kernel
unprivileged-userns and Landlock matrix on Kali, Python-bytecode decompiler
coverage per Python version. Until then these adapters are marked unverified and
none of them is on the critical path for the first release.


## Addendum: Bubble Tea start-up probe

Verified while building `inspect`: bubbletea v1.3.10 has a package initialiser
(`tea_init.go`) that calls `lipgloss.HasDarkBackground()`, which writes an
`ESC ] 11 ; ?` colour query and an `ESC [ 6 n` cursor query to the terminal and
waits for the reply. Linking the library therefore affects every run of the
program, not only the interactive command. Decision: keep it in a separate
executable (`unpackr-inspect`) and enforce that with a boundary test
(`TestMainBinaryDoesNotLinkTheTerminalUI`). The v2 line, which the plan said to
check, is noted in the library's own source as removing this workaround; it was
not evaluated here.

## Addendum: clean-install verification of the .deb

`packaging/verify-install.sh` installs the package with `apt` into a clean
container and checks: checksum, installation with no other packages, both
binaries, static linking, `--version`, `doctor`, info/quick/deep analysis of a
real system executable, an HTML report, the polite refusal of `inspect` without a
terminal, that sandbox status is stated, the man page (roff lint with `mandoc`
plus section check), the three completion files, the licence and notices, and
clean removal.

Run locally on amd64 against `kalilinux/kali-rolling`, `ubuntu:24.04`,
`ubuntu:22.04` and `debian:12`: all checks pass, and `doctor` reports full
confinement (Landlock ABI 7, seccomp, no_new_privs) inside the containers.
Two things the script taught: minimised container images tell dpkg to skip man
pages and docs (the script lifts that, because it is a property of the image),
and `man` itself is a stub in the Ubuntu image (the page is checked with
`mandoc` instead).

The CI `package` job runs the same script on a native amd64 runner and a native
arm64 runner, which is the only place the arm64 package is executed; no
emulation is available where this was developed. Not verified: Kali on real
hardware or a virtual machine, installation through a Kali ISO or repository
mirror, and `apt` dependency behaviour on release candidates of those
distributions.


## Addendum: radare2 adapter (findings that changed the design)

Verified on radare2 5.5.0 (Ubuntu 24.04 package) with a gcc-built ELF and a
MinGW-built PE; the adapter's tests run the real tool inside the exec sandbox.

* `radare2 -S` ("sandbox mode") did **not** stop `!cmd`; `-e cfg.sandbox=true`
  does, but only once the file is open (set at start-up, radare2 cannot open the
  sample). Even then a `!` inside backticks ran. So the strict name allow-list is
  the defence, and the process sandbox is the backstop.
* `>>` is radare2's append-redirect: a marker such as `<<X>>` printed as `<<X` and
  created a file. Markers are now plain words carrying a random token.
* `afl` adds a `-> N` column for some functions; the parser handles it.
* Progress output prefixes lines with an ANSI "clear line" sequence; it is stripped
  before parsing.
* On a PE, `axtj sym.imp.LIB.dll_Name` finds the references; the packed
  `putty.exe` in the PE library's test data gave none, which was the file, not the
  tool (a MinGW-built program resolves correctly).
* Not verified: Rizin, Mach-O, any radare2 other than 5.5.0 (Kali ships a newer
  one), 32-bit PE, and large or packed samples.

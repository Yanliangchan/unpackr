# Obfuscation: what UNPACKR recovers, flags and cannot see

Static analysis only. Nothing is executed or emulated. Every result below is
either an **observation** (these bytes really decode to this text) or an
**inference** (so the author probably hid it); reports label which.

## Recovered

| Technique | How it is found | Confidence |
|---|---|---|
| Single-byte XOR or ADD encoded strings (data or code) | The difference between neighbouring bytes does not depend on the key (`e[i]^e[i+1] = p[i]^p[i+1]`; likewise for ADD). A list of about 30 markers (`http://`, `/bin/sh`, `cmd.exe`, `VirtualAlloc`, …) is searched for by those differences in one pass, and the key follows from the first byte. No keys are tried. | high: a marker of 6+ bytes matching by chance is about 256^-5 per position |
| Strings built on the stack by constant stores (x86/x86-64: byte, word and dword immediates, `movabs` + register store) | Consecutive stores are joined by frame offset. The assembled frame is searched for text and for XOR/ADD-encoded markers. | medium for plain text (byte-pattern match, not disassembly); high for an encoded marker |
| Executables embedded as base64 | The base64 form of an MZ or ELF header begins a long, valid base64 run. | high |
| Run-time symbol resolution (`dlsym`, `GetProcAddress`, `LdrGetProcedureAddress`) | Imports. Reported as a low-severity capability because plugin systems do the same. | weak |
| Large high-entropy appended data | Overlay is at least 25% of the file with entropy 7.5 or more. An entropy-family signal: it can raise "unknown" but never decide a verdict on its own. | weak to moderate |
| Packer with its markers removed | ELF with no section headers, no interpreter and a writable segment reserving at least 3x (and 8 KiB more than) what the file supplies, which is the layout of an in-memory unpacker. | moderate, so with another structural signal: `likely-packed`, no family named |

A plain stack string is listed only when it contains a marker or looks like a
URL, address or domain, because compilers build ordinary constant text on the
stack too. On 271 real system binaries (Go, C, C++) this produced no
"obfuscated" verdict and no listed string.

## Code patterns (`-d`)

A bounded linear disassembly of the executable sections (x86 and x86-64 only,
using golang.org/x/arch). Nothing is executed and no control-flow graph is built.

| Pattern | What is matched | Strength |
|---|---|---|
| module walking | a read of the PEB through `fs:[0x30]` (32-bit) or `gs:[0x60]` (64-bit), then the loader-data and module-list offsets within the next 14 instructions | moderate |
| API-name hashing | `ror 13` in a loop that loads a byte, accumulates with add/xor/sub and branches back to the load within 48 bytes (the widely copied form; other rotate loops are ordinary hash functions and are ignored) | moderate |
| control-flow flattening | within a 4 KB window, at least 12 distinct large (at least 0x10000) constants that are both stored (`mov`) and compared (`cmp`), i.e. state values | moderate |

Verification: hand-assembled byte sequences for each idiom and for near misses
(PEB read without a walk, other segment offsets, rotate without a loop, a large
`switch` with no matching stores); random data produces nothing; a sweep of 271
real system binaries (77 MB of code) produced no site. Two thresholds were set
from that sweep: ordinary code reached 6 shared constants by accident in four
files, hence the minimum of 12, and generic rotate-and-add loops (69 sites in
ordinary hashing code) are not reported.

Limits: a small flattened function with fewer than 12 states is missed; hashing
with another rotate amount, or hashing done with other instructions, is missed;
nothing is tuned on real malware because none was available here. Patterns that
need function recovery (opaque predicates, virtualised code) are not attempted.
Results are heuristic, medium-confidence observations at most.

## State

`obfuscated` means encoded text was recovered and no packer was identified. It
is not evidence that the program body is compressed or encrypted. Its note says
what could not be looked for.

## Not recovered (so absence of a result is not a clean result)

* Stack-built strings on architectures other than x86 and x86-64 (ARM, AArch64 and
  others): the recogniser matches x86 instruction encodings. Encoded strings
  kept in data are architecture-independent and are still found.
* Multi-byte or rolling keys, RC4, AES, custom ciphers, UTF-16 encodings.
* Strings assembled through computation or loops, and any string that holds
  none of the markers (the search finds known text, not arbitrary text).
* API hashing and PEB walking (needs disassembly), control-flow flattening,
  opaque predicates, virtualising protectors (VMProtect, Themida).
* .NET protectors beyond known metadata markers; Go/Rust obfuscators.
* Packers other than UPX cannot be unpacked; they can only be flagged.

## Cost

About 4 ms per MB for the encoded-string search. Both difference scans use
bounded memory and the input is capped at 64 MiB for this stage.

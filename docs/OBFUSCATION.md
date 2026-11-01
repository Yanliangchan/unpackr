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

## State

`obfuscated` means encoded text was recovered and no packer was identified. It
is not evidence that the program body is compressed or encrypted. Its note says
what could not be looked for.

## Not recovered (so absence of a result is not a clean result)

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

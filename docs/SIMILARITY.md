# Similarity

UNPACKR does not invent a fuzzy hash or a percentage. It reports measurements
from established algorithms, and one documented structural overlap, and says
plainly what they do not mean.

## What is computed

| Measurement | Algorithm | Reading |
|---|---|---|
| ssdeep | the reference context-triggered piecewise hash (Go port `glaslos/ssdeep`) | score 0-100; higher is closer; 0 means no match, which includes incomparable block sizes |
| TLSH | Trend Micro's locality-sensitive hash (Go port `glaslos/tlsh`) | distance; 0 identical, larger is less alike. Needs at least 50 bytes |
| Structural overlap | weighted mean of the property overlaps below | 0 to 1; shown only when at least 3 properties could be compared |

Hashes are written in the reference tools' format (`T1` prefix and upper case
for TLSH). **The Go ports are validated against the reference implementations in
the test suite**: hashes are byte-identical to the `ssdeep` command and `py-tlsh`
on synthetic and real binaries, and every pairwise TLSH distance and ssdeep
score agrees (including non-zero ssdeep scores). The test is skipped when the
reference tools are not installed.

## Structural overlap

Each property is compared as a set (Jaccard index: shared items divided by all
distinct items). A property is omitted, never counted as zero, when either file
lacks the data.

| Property | Items | Weight | Comparable when |
|---|---|---|---|
| imports | `library!function` pairs | 0.30 | both have at least 5 imports |
| strings | MinHash sketch (128 slots) of every string of 8 or more characters | 0.20 | both have strings |
| sections | name, permissions and raw size in 4 KiB steps | 0.15 | both have at least 3 sections |
| indicators | type and value | 0.15 | both have some |
| capabilities | inferred capability ids | 0.10 | both have some |
| import hash | equality of the pefile-compatible import hash | 0.10 | both have one |

`overlap = sum(weight x score) / sum(weight)` over the comparable properties.
The weights are fixed and **not calibrated** on any corpus; they only say that
import and string overlap are stronger signals than a shared section list. The
MinHash estimate has a standard error of about 0.09.

## What it does not mean

- Not a probability, and not evidence of a shared origin or family. UNPACKR makes
  no attribution from similarity.
- Statically linked language runtimes make unrelated programs resemble each
  other. Two different Go programs are close in TLSH largely because they carry
  the same Go runtime (observed on the test fixtures: a Windows and a Linux build
  of the same trivial program are TLSH "related"). Packed files resemble their
  packer, not their payload; unpack first.
- ssdeep is fragile to scattered small edits; TLSH is more tolerant of them.
  Neither says what changed.
- The TLSH bands (about 30 and 100) and the ssdeep bands are the conventional
  rules of thumb, not tuned for this tool. The raw numbers are always shown.

## Where it appears

- `unpackr similar <file|sha256-prefix>`: compares with every stored sample
  (hashes against all of them; the structural overlap for the closest
  candidates and for samples sharing an import hash, section layout or host).
- `unpackr -c a b`: a similarity block in the comparison.
- Fuzzy hashes are stored as pivot features, so `unpackr db find --kind tlsh <hash>`
  works too.

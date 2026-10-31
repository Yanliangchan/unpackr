# UNPACKR report: demo.exe

*Static analysis. UNPACKR <version>.*

## Executive summary

- File demo.exe: 1234 bytes, SHA-256 abababababababababababababababababababababababababababababababab.
- Identified as PE32+ from its content, not its name.
- This is a static analysis: the sample was never executed. Confidence labels describe how well the evidence supports a statement, and are not probabilities.
- 1 analysis stage(s) are not available in this build, so their absence is not a clean result: anomaly-detection.

Findings by severity: high 0, medium 0, low 0, informational 1.

## File metadata and hashes

| Property | Value |
| --- | --- |
| Name | demo.exe |
| Size | 1234 bytes |
| SHA-256 | `abababababababababababababababababababababababababababababababab` |
| SHA-1 | `s` |
| MD5 | `m` |

Format: **PE32+**. Scores are structural validity out of 100, not probabilities.

## Findings

Class: *observation* (read from the file), *inference* (derived by a named rule), *hypothesis* (weakly supported). Confidence is ordinal and is not a probability.

| Finding | Class | Severity | Confidence | Why this confidence | Evidence |
| --- | --- | --- | --- | --- | --- |
| Format: PE32+ | observation | informational | high | all checks passed | e1 |

## Evidence

| Id | Kind | Value | File offset | Section | Source |
| --- | --- | --- | --- | --- | --- |
| e1 | structure-check | `PE signature` | 0x80 |  | identification  |

## Recommendations

1. Look closer.
2. Handle the sample only in an isolated, disposable environment; this report is static and cannot rule out behaviour.
3. Confirm any capability or indicator by inspecting the code that uses it (disassembly or decompilation) before relying on it.

## Limits of this report

Stages not available in this build (their absence is not a clean result):

- anomaly-detection


| Module | Status | Time (ms) | Sandbox |
| --- | --- | --- | --- |
| identification | ok | 3 | n/a |


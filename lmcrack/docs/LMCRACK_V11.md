# lmcrack v11 Printable-Alphabet Mode

## Purpose

Version 11 is a specialized bitsliced LM cracker for the distinct printable
ASCII characters that remain after LM password normalization. It extends the
frozen-alphabet approach used by v8 and v9 to passwords containing spaces and
punctuation.

V11 does not replace or renumber the existing modes:

| Mode | Frozen alphabet |
|---|---|
| v8 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| v9 | `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| v10 | Unassigned |
| v11 | Digits, uppercase letters, space, and ASCII punctuation |

## Frozen alphabet

The exact 69-character alphabet and its ordering are:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

The character groups are ordered as follows:

1. `0` through `9`
2. `A` through `Z`
3. Space
4. ASCII punctuation in ascending character-code order

Lowercase letters are intentionally absent because LM hashing converts them
to uppercase. Control bytes and non-ASCII bytes are not part of v11; use the
general v7 mode when a different alphabet is required.

The alphabet order is part of the v11 compatibility contract. Unlike custom
alphabets, it is not sorted by the command-line parser.

## Candidate ordering and size

Passwords are enumerated at lengths 1 through 7. Position zero is the
fastest-changing radix-69 digit, matching the established lmcrack convention:

```text
0, 1, ... ~, 00, 10, 20, ...
```

| Length | Candidates at length | Cumulative candidates |
|---:|---:|---:|
| 1 | 69 | 69 |
| 2 | 4,761 | 4,830 |
| 3 | 328,509 | 333,339 |
| 4 | 22,667,121 | 23,000,460 |
| 5 | 1,564,031,349 | 1,587,031,809 |
| 6 | 107,918,163,081 | 109,505,194,890 |
| 7 | 7,446,353,252,589 | 7,555,858,447,479 |

## Usage

Select v11 explicitly. The frozen alphabet is supplied automatically:

```powershell
build-avx2\lmcrack 695109AB020E401C -v11 -s '!' -e '!' -t 1
```

The example recovers the one-character password `!`. The start and end values
are inclusive. Quote values containing spaces or shell metacharacters; for
example, a one-character space is written as `-s " " -e " "` in PowerShell.

Supplying `-c` is unnecessary. If it is supplied with v11, it must match the
frozen alphabet exactly and in the documented order.

## Implementation

V11 uses:

- a seven-plane radix-69 bitsliced counter;
- direct Boolean conversion from counter digits to printable ASCII key planes;
- the shared schedule-free bitsliced DES rounds and staged target matcher;
- the compiled scalar, SSE2, AVX2, AVX-512, or ARM64 NEON backend.

The steady-state loop does not construct a password string or DES key schedule
for every candidate. A password is reconstructed only when a lane matches.

## Validation

Tests cover every alphabet symbol, radix carries, length transitions,
non-aligned SIMD ranges, partial tail batches, key-plane conversion against the
generic transpose reference, DES worker recovery, and command-line recovery.
Scalar, SSE2, and AVX2 runtime tests pass. The AVX-512 path compiles on the
current x86-64 build host; NEON tests are registered for ARM64 builds.


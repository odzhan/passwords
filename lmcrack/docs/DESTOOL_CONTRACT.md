# destool v1 Contract

This document freezes the first-release interface and key interpretation for
`destool`. Later implementation steps must preserve this contract unless the
checklist and this document are deliberately revised together.

## Command line

```text
destool <plaintext-hex> <ciphertext-hex> -a <1-7> -l <1-7>
        [-t <threads>] [-s <start-key-hex>] [-e <end-key-hex>]
```

- `plaintext-hex` and `ciphertext-hex` are exactly 16 case-insensitive
  hexadecimal characters, representing one raw 8-byte DES block in external
  byte order. Prefixes, separators, padding, modes, and IVs are not accepted.
- `-a` selects one frozen alphabet from the table below.
- `-l` is mandatory and selects an exact candidate length from one through
  seven bytes.
- `-t` selects 1 through 32 worker threads. Its default is the available
  hardware concurrency, clamped to that range.
- `-s` and `-e` are optional inclusive range endpoints. Each is encoded as
  exactly `2 * length` hexadecimal characters and must belong to the selected
  alphabet. The defaults are the first and last keys of the exact-length
  space. Internally, worker ranges are half-open.
- Position zero is the first displayed key byte and the fastest-changing
  candidate digit. Alphabet table order defines each digit's numeric value.

## Frozen alphabets

| ID | Canonical byte sequence |
|---:|---|
| 1 | Every byte from `00` through `FF` |
| 2 | `0123456789` |
| 3 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| 4 | `abcdefghijklmnopqrstuvwxyz` |
| 5 | `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| 6 | `0123456789abcdefghijklmnopqrstuvwxyz` |
| 7 | `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` |

The user selects an alphabet by ID; arbitrary alphabets are not accepted.

## Key interpretation

A candidate consists of exactly `length` raw bytes. It is right-padded with
zero bytes to seven bytes and transformed by the existing LM 7-byte-to-DES-key
operation:

```text
d0 =  k0 >> 1
d1 = (k0 & 01) << 6 | k1 >> 2
d2 = (k1 & 03) << 5 | k2 >> 3
d3 = (k2 & 07) << 4 | k3 >> 4
d4 = (k3 & 0F) << 3 | k4 >> 5
d5 = (k4 & 1F) << 2 | k5 >> 6
d6 = (k5 & 3F) << 1 | k6 >> 7
d7 =  k6 & 7F
DES key byte i = (di << 1) with odd parity applied
```

DES ignores the parity bit in each key byte. Alphabet 1 at length 7 therefore
covers all 56 effective DES key bits. The reported candidate is the canonical
seven-byte material, not necessarily the original eight-byte DES key encoding.
Literal eight-byte DES-key enumeration is outside the first-release scope.

## Results and exit status

On success, destool reports:

- the candidate bytes as uppercase hexadecimal;
- an escaped representation in which printable ASCII is shown directly and
  every other byte is written as `\xNN`;
- the corresponding eight-byte DES key with canonical odd parity;
- tested candidate count, elapsed time, and candidate rate.

Exit statuses are:

| Status | Meaning |
|---:|---|
| 0 | A matching effective key was found |
| 1 | The selected key space was exhausted without a match |
| 2 | Command-line input was invalid |
| 3 | Allocation, threading, or another internal operation failed |

The first release accepts one plaintext/ciphertext pair and returns the first
matching candidate in scheduling order. Verification against multiple pairs,
CBC preprocessing, 3DES, and benchmarking are separate extensions.

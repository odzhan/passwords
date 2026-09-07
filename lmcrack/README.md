# lmcrack

`lmcrack` searches the key space for the password corresponding to an LM hash.
Use it only on hashes and systems you are authorized to test.

## Source layout

- `src/legacy` contains the scalar v1 through v6 DES implementations.
- `src/bitslice/common` contains backend-neutral bitslice primitives and the
  shared fixed-alphabet DES path.
- `src/bitslice/v7`, `v8`, and `v9` contain version-specific workers and
  candidate generation.
- `src/destool` contains the standalone known-plaintext DES key-search tool.
- `tests/bitslice`, `tests/destool`, `tests/v8`, and `tests/v9` contain unit and differential
  tests; `tests/integration` contains command-line tests.
- `tools` contains profiling and benchmarking programs.
- `cmake` contains reusable SIMD and test-target configuration.

## Building

Configure a separate Release build directory for each SIMD backend. CMake adds
the appropriate compiler switch (`/arch:...` with MSVC or `-m...` with GCC and
Clang); MinGW AVX builds also receive `-mstackrealign` for Windows thread-stack
alignment.

```powershell
# Portable x86-64/SSE2
cmake -S . -B build-sse2 -DCMAKE_BUILD_TYPE=Release `
  -DLMCRACK_ENABLE_SSE2=ON -DLMCRACK_ENABLE_AVX2=OFF `
  -DLMCRACK_ENABLE_AVX512=OFF
cmake --build build-sse2 --config Release

# AVX2 (recommended on supported x86-64 CPUs)
cmake -S . -B build-avx2 -DCMAKE_BUILD_TYPE=Release `
  -DLMCRACK_ENABLE_AVX2=ON -DLMCRACK_ENABLE_AVX512=OFF
cmake --build build-avx2 --config Release

# AVX-512 (only for CPUs that expose AVX-512F)
cmake -S . -B build-avx512 -DCMAKE_BUILD_TYPE=Release `
  -DLMCRACK_ENABLE_AVX512=ON
cmake --build build-avx512 --config Release

# Native ARM64: NEON is enabled automatically and needs no extra compiler flag
cmake -S . -B build-arm64 -DCMAKE_BUILD_TYPE=Release `
  -DLMCRACK_ENABLE_NEON=ON
cmake --build build-arm64 --config Release
```

Release builds enable link-time optimization when the toolchain supports it.
For a binary used only on the machine that builds it, add
`-DLMCRACK_NATIVE_CPU=ON`; this selects `-march=native` on x86 or
`-mcpu=native` on ARM with GCC/Clang. Do not use native tuning for distributable
binaries or cross-compilation.

Run the configured test suite with:

```powershell
ctest --test-dir build-avx2 -C Release --output-on-failure
```

Both `lmcrack` and `destool` are produced by these CMake builds and use the
same selected SIMD backend and optimization settings. The legacy GNU and
Windows Makefiles build lmcrack only; CMake is the supported build path for
destool.

## Using lmcrack

Pass one 16-hex-character half of an LM hash, followed by the search options.
The default alphabet is uppercase ASCII. This example searches passwords from
`A` through `ZZZZZZZ` with 14 threads using the optimized scalar v4 algorithm:

```powershell
build-avx2\lmcrack 1FB363FEB834C12D -v4 -s A -e ZZZZZZ -t 14
```

Use v8 for the fixed uppercase alphabet:

```powershell
build-avx2\lmcrack 1FB363FEB834C12D -v8 -s A -e ZZZZZZ -t 14
```

Use v9 for the fixed digits-and-uppercase alphabet. When `-c` is omitted, v9
automatically selects `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ`:

```powershell
build-avx2\lmcrack 1FB363FEB834C12D -v9 -s 0 -e ZZZZZZ -t 14
```

For an arbitrary custom alphabet, use the general v7 bitslice implementation.
Quote alphabets containing shell metacharacters:

```powershell
build-avx2\lmcrack 1FB363FEB834C12D -v7 -c ABCDEF0123456789 -s A -e FFFFFF -t 8
```

`-s` and `-e` are inclusive. Omit them to use the first and last candidates
for the selected alphabet and supported password lengths. Run
`build-avx2\lmcrack -h` for every option and version description.

## lmcrack optimized versions

- `-v7` is the general bitslice implementation and supports arbitrary accepted
  alphabets.
- `-v8` is specialized for the exact alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ`.
- `-v9` is specialized for the exact alphabet
  `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` and password lengths 1 through 7.

The command-line parser uppercases, sorts, and deduplicates custom alphabets.
Consequently, v9 always uses digits-first base-36 order, regardless of the
order supplied to `-c`. Character position zero is the fastest-changing digit.
If `-v9` is selected without `-c`, the fixed v9 alphabet is selected
automatically.

Use `lmcrack -h` for the complete version descriptions and command-line
options. The `v9_profile` target is a developer utility that reports the cost
of candidate counting, key-plane conversion, DES, target matching, and atomic
progress accounting.

## Using destool

`destool` takes one known 8-byte plaintext/ciphertext pair, both written as 16
hexadecimal characters, and searches for exact-length key material:

```text
destool <plaintext-hex> <ciphertext-hex> -a <alphabet-id> -l <length>
        [-t <threads>] [-s <start-key-hex>] [-e <end-key-hex>]
```

For example, this searches all one-byte decimal candidates and recovers `0`:

```powershell
build-avx2\destool 4B47532140232425 25AD3B83FA6627C7 -a 2 -l 1 -t 1
```

This searches three-character uppercase key material using all available
hardware threads:

```powershell
build-avx2\destool 0123456789ABCDEF 85E813540F0AB405 -a 3 -l 3
```

Range endpoints are inclusive hexadecimal encodings of the candidate bytes,
not text arguments. This restricts a one-byte uppercase search to `A` through
`F` (`41` through `46` in ASCII):

```powershell
build-avx2\destool 4B47532140232425 7584248B8D2C9F9E -a 3 -l 1 -s 41 -e 46 -t 1
```

The frozen alphabet IDs are:

| ID | Candidate bytes |
|---:|---|
| 1 | `00` through `FF` |
| 2 | `0-9` |
| 3 | `A-Z` |
| 4 | `a-z` |
| 5 | `0-9`, `A-Z` |
| 6 | `0-9`, `a-z` |
| 7 | `0-9`, `a-z`, `A-Z` |

The length is exactly 1-7 bytes. `destool` zero-pads that material to seven
bytes and applies the LM 7-byte-to-DES-key expansion. It therefore does not
search literal eight-byte DES keys; the displayed DES key is the expanded key.
Recovered keys are always printed in hexadecimal and also in an escaped text
form, so zero and non-printable bytes remain visible. Run
`build-avx2\destool --help` for full range semantics and exit statuses.

For developer profiling, build and run the phase-isolating utility:

```powershell
cmake --build build-avx2 --target destool_profile --config Release
build-avx2\destool_profile 50000
```

It reports per-batch costs for counting, alphabet mapping, DES, target
matching, atomic progress, stop polling, and the combined hot path, alongside
the equivalent v9 radix-36 generator costs.

## SIMD support

The bitslice implementation has scalar, SSE2, AVX2, AVX-512F, and ARM64 NEON
backends. The build selects one backend at compile time; it does not perform
runtime CPU dispatch. Build the lowest common backend required by the target
machines, or distribute separate binaries for different instruction sets.

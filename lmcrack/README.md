# lmcrack

`lmcrack` searches the key space for the password corresponding to an LM hash.
Use it only on hashes and systems you are authorized to test.

## Source layout

- `src/legacy` contains the scalar v1 through v6 DES implementations.
- `src/bitslice/common` contains backend-neutral bitslice primitives and the
  shared fixed-alphabet DES path.
- `src/bitslice/v7`, `v8`, and `v9` contain version-specific workers and
  candidate generation.
- `tests/bitslice`, `tests/v8`, and `tests/v9` contain unit and differential
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

## Optimized versions

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

Example:

```powershell
build-avx2\lmcrack 1FB363FEB834C12D -v9 -t 14
```

Use `lmcrack -h` for the complete version descriptions and command-line
options. The `v9_profile` target is a developer utility that reports the cost
of candidate counting, key-plane conversion, DES, target matching, and atomic
progress accounting.

## SIMD support

The bitslice implementation has scalar, SSE2, AVX2, AVX-512F, and ARM64 NEON
backends. The build selects one backend at compile time; it does not perform
runtime CPU dispatch. Build the lowest common backend required by the target
machines, or distribute separate binaries for different instruction sets.

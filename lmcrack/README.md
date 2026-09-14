# lmcrack

`lmcrack` searches the key space for the password corresponding to an LM hash.
Use it only on hashes and systems you are authorized to test.

## AVX2 results — 2026-09-14

The final AVX2 rebuild passed **89/89 tests**. Measurements below are actual
CLI throughput on an Intel Core Ultra 5 135U (12 cores, 14 logical processors),
Windows, GCC 13.2, Release `-O3`, LTO enabled, native CPU tuning disabled.
Scalar lookup tables use the default layout; **v5 uses three streams**
(`LMCRACK_V5_STREAMS=3`). V5x always uses three streams and AVX2 schedule merging.

Each cell gives the **median million candidates/second (minimum–maximum)**
over three five-second trials. Runs used one or twelve worker threads and
seven-character search ranges against a synthetic zero hash. V1-v8 and v5x
use A-Z, v9 uses digits/A-Z, and v11 uses its 69-character printable alphabet.

| Version | 1 thread: M candidates/s | 12 threads: M candidates/s |
| --- | ---: | ---: |
| v1 | 6.50 (6.35–6.72) | 36.70 (35.27–38.11) |
| v2 | 8.61 (8.54–8.65) | 43.26 (40.98–44.94) |
| v3 | 16.02 (14.92–17.40) | 101.35 (98.27–111.04) |
| v4 | 18.36 (17.26–19.53) | 93.96 (93.63–96.23) |
| v5 | 36.67 (30.46–37.65) | 138.44 (119.33–151.84) |
| v5x | 30.81 (28.58–30.82) | 128.81 (126.28–146.47) |
| v6 | 15.14 (13.56–15.16) | 99.15 (94.55–99.80) |
| v7 | 54.94 (44.09–57.95) | 220.52 (218.03–233.84) |
| v8 | 123.66 (115.90–140.89) | 478.71 (439.21–530.61) |
| v9 | 179.11 (166.55–180.26) | 449.25 (438.80–452.28) |
| v11 | 164.76 (153.09–167.78) | 450.51 (440.47–485.52) |

Version 10 is unassigned. AVX2 is the build configuration; v1-v6 still execute
scalar DES, and v5x uses AVX2 only for schedule merging. These are sequential
throughput snapshots, not controlled speedup measurements. No affinity or
frequency control was applied; scheduling, temperature, and power limits can
affect the results substantially. Differing alphabets also limit comparisons.
Each sample is the final cumulative CLI rate before the benchmark process is
stopped. See [all raw trials](docs/AVX2_FINAL_RESULTS.md); earlier experiment
reports remain historical A/B results.

Reproduce from the `lmcrack` directory using the same GCC toolchain:

```powershell
cmake -S . -B build-avx2 -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release `
  -DLMCRACK_ENABLE_AVX2=ON -DLMCRACK_ENABLE_AVX512=OFF `
  -DLMCRACK_ENABLE_PAIR64=OFF -DLMCRACK_ENABLE_PAIR256=OFF `
  -DLMCRACK_ENABLE_LTO=ON -DLMCRACK_NATIVE_CPU=OFF -DLMCRACK_V5_STREAMS=3
cmake --build build-avx2 -j 8
ctest --test-dir build-avx2 --output-on-failure
./tools/benchmark_versions.ps1 -Executable ./build-avx2/lmcrack.exe `
  -Seconds 5 -Repetitions 3 -Threads 1,12
```

The portable v5 default remains two streams; explicitly select three to
reproduce this table. Benchmarking all modes at both thread counts takes
approximately six minutes.

## Source layout

- `src/legacy` contains the scalar v1 through v6 DES implementations.
- `src/bitslice/common` contains backend-neutral bitslice primitives and the
  shared fixed-alphabet DES path.
- `src/bitslice/v7`, `v8`, `v9`, and `v11` contain version-specific workers and
  candidate generation.
- `src/destool` contains the standalone known-plaintext DES key-search tool.
- `tests/bitslice`, `tests/destool`, `tests/v8`, `tests/v9`, and `tests/v11`
  contain unit and differential tests; `tests/integration` contains
  command-line tests.
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

Use v11 for every distinct printable ASCII character after LM uppercasing.
It freezes digits first, uppercase letters second, then space and punctuation:

```text
0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

The alphabet contains 69 characters; lowercase is omitted because LM hashing
converts it to uppercase. Shell-sensitive range characters should be quoted:

```powershell
build-avx2\lmcrack 695109AB020E401C -v11 -s '!' -e '!' -t 1
```

See [the v11 mode documentation](docs/LMCRACK_V11.md) for the complete frozen
alphabet contract, candidate ordering, key-space sizes, and validation status.

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
- `-v11` is specialized for the 69-character printable LM alphabet: digits,
  uppercase letters, space, and ASCII punctuation. Its exact frozen order is
  shown above.

Version 10 is currently unassigned; the existing v8 and v9 meanings were kept
stable for command-line compatibility.

The command-line parser uppercases, sorts, and deduplicates custom alphabets.
Consequently, v9 always uses digits-first base-36 order, regardless of the
order supplied to `-c`. Character position zero is the fastest-changing digit.
If `-v9` or `-v11` is selected without `-c`, its fixed alphabet is selected
automatically. V11 preserves its documented category order rather than sorting
the alphabet.

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

### Comparing v7 pipeline changes

Build the `v7_profile` target and run `v7_profile 20000` to compare the original
scheduled DES pipeline with the current schedule-free pipeline in one binary.
It reports direct phase timings and median/minimum/maximum over five repeats
for three alphabets, and verifies matching encrypted states before timing.
The combined pipeline includes generation, transpose, encryption, matching,
and lane extraction, but excludes thread startup and worker progress atomics.
Its phase timings include an output-consumption barrier; they should not be
expected to sum exactly to the combined timing. On MSVC the barrier uses byte
reads, which add overhead proportional to output size. Use a consistent
compiler and build configuration for comparisons. No CPU affinity is set.

### V7 executable comparison

For actual v7 CLI comparisons on Windows, configure
`-DLMCRACK_BUILD_COMPARISONS=ON`, then explicitly build targets `lmcrack`,
`lmcrack_reference_transpose`, and `lmcrack_reference_lane`. The reference
targets use the same compiler options and Release LTO setting as `lmcrack`.
The first retains both the old transpose and lane scanner; the second retains
only the old lane scanner. All three use schedule-free DES and staged matching.

Run `tools/benchmark_v7_comparison.ps1 -BuildDirectory <build-directory>`.
It runs three five-second trials for each of three alphabets at 1 and 12
threads, rotating executable order and reporting median, range, and raw rates.
Use `-Threads` for machines with fewer logical processors; the script rejects
a mismatch between requested and actual thread counts. It searches synthetic
targets, stops only the benchmark processes it launches, and uses each trial's
last cumulative CLI progress rate. No affinity or clock control is applied.
Large trial variation means small differences should not be treated as proven
speedups. Reference executables are excluded from the default build.

Recorded results and raw trials are in [V7 CLI comparison](docs/V7_CLI_COMPARISON.md).

### Scalar comparison

With `LMCRACK_BUILD_COMPARISONS=ON`, explicitly build targets
`lmcrack_scalar_default`, `lmcrack_scalar_pair64`, and `lmcrack_scalar_pair256`.
These select the existing scalar DES lookup layouts with otherwise identical
build settings. Run `tools/benchmark_scalar.ps1 -BuildDirectory <build-directory>`
for a v4/v5/v6 matrix using A-Z, three five-second trials, and 1/12 threads.
`-Seconds`, `-Repetitions`, and `-Threads` override those defaults. The shared
measurement engine rotates layout order and reports raw trials plus medians.
Results reflect the tested CPU, alphabet, and compiler; paired tables are not
automatically selected based on these measurements.

Validate each comparison executable with:

```text
cmake -DLMCRACK_EXE=<absolute-path-to-executable> -P tests/integration/scalar_cli_differential.cmake
```

This compares recovery by v4/v5/v6 against v1 using known hashes at lengths
1-7, a length transition, and an uneven multithreaded range.

See [scalar comparison](docs/SCALAR_COMPARISON.md) for measured results and
the selected baseline for further tuning.

### Default, 64 KiB, and 256 KiB DES tables

These are scalar DES substitution/permutation lookup tables, not the separate
character-pair key-schedule tables. Sizes below are bytes (KiB), not kilobits,
and describe the round lookup arrays rather than total program memory.

| Layout | Organization | Lookups per round | Tradeoff |
| --- | --- | ---: | --- |
| Default, 2 KiB | Eight tables of 64 32-bit entries | 8 | Small footprint and simple six-bit indexes |
| Pair64, 64 KiB | Four tables of 4,096 32-bit entries | 4 | Combines two S-box contributions; packs two six-bit indexes into twelve bits |
| Pair256, 256 KiB | Four tables of 16,384 32-bit entries | 4 | Retains two gap bits in a fourteen-bit index, avoiding dense packing but using a larger allocation |

Pair256's gap-bit layout contains repeated values and unused index positions;
it does not represent more distinct S-box combinations than Pair64. Fewer
lookups can help, but the larger footprint and different indexing arithmetic
can outweigh that saving. Cache effects were not measured directly here.

**Which versions use the selection?** V1/v2 use it through the common DES
encryptor, v3 through the common round macro, and v5/v6/v5x through their own
conditional round macros. V4's main pair loop explicitly uses the default
`des_SPtrans` tables regardless of the build setting; its v3 fallback follows
the setting. The bitsliced v7/v8/v9/v11 DES paths use Boolean circuits and do
not use these round lookup layouts. Support for a setting does not imply a
measured speed benefit: v1-v3 and v5x have not had a table-layout speed comparison.

The measured matrix below used Core Ultra 5 135U, GCC 13.2 Release/LTO,
seven-character A-Z ranges, three five-second trials per case, and rotating
layout order. Values are median **million candidates/second**. **V5 used two
streams in this earlier controlled layout comparison**, unlike the three-stream
v5 in the final AVX2 results at the top of this README.

| Version | Threads | Default build | Pair64 build | Pair256 build |
| --- | ---: | ---: | ---: | ---: |
| v4* | 1 | 18.55 | 18.98 | 17.87 |
| v4* | 12 | 105.98 | 116.75 | 108.93 |
| v5, two streams | 1 | **29.51** | 22.09 | 24.88 |
| v5, two streams | 12 | **140.62** | 87.52 | 81.08 |
| v6 | 1 | **18.39** | 13.58 | 17.77 |
| v6 | 12 | **106.28** | 66.97 | 61.02 |

*V4 uses default round tables in all three builds for these ranges. Its timing
differences must not be attributed to changing the round table layout; runtime
variation and other build effects are not isolated by this measurement.*

**Recommendation:** keep default tables for v5 and v6 on this host. Neither
paired layout showed a benefit for either version; Pair64 was about 25% slower
and Pair256 about 16% slower for single-thread v5. No measured version currently
establishes a paired-table advantage. Results on other CPUs, alphabets, or
stream counts require new measurements. Raw trials and validation are in
[the scalar comparison report](docs/SCALAR_COMPARISON.md).

Choose one layout at configure time; the two pair options are mutually exclusive:

```text
Default: -DLMCRACK_ENABLE_PAIR64=OFF -DLMCRACK_ENABLE_PAIR256=OFF
64 KiB:  -DLMCRACK_ENABLE_PAIR64=ON  -DLMCRACK_ENABLE_PAIR256=OFF
256 KiB: -DLMCRACK_ENABLE_PAIR64=OFF -DLMCRACK_ENABLE_PAIR256=ON
```

Use the comparison targets and benchmark command in the preceding scalar
comparison section to repeat the matrix without changing the main binary's
table selection.

### How v5 works and why it leads the scalar variants

V5 is a table-based scalar DES implementation derived from v4. Each candidate
encrypts the fixed LM plaintext `KGS!@#$%` with a key derived from up to seven
password bytes. V5 avoids rebuilding the complete DES key schedule for each
candidate and overlaps independent encryptions within a single worker thread.
It does not use bitslicing; its encryption rounds use scalar integer operations
and table lookups even in an AVX2 build.

The work is organized as follows:

1. **Reuse schedule contributions.** Precomputed tables hold the DES schedule
   contributions of individual characters and every pair in the first two
   password positions. Contributions from the remaining positions are combined
   into an invariant schedule for the current pair block, updated when those
   positions change. A one-character starting candidate uses the v3 fallback.
2. **Merge only the words a round needs.** Each round ORs its pair-schedule
   words with the corresponding invariant words. V5 therefore avoids writing
   and rereading a complete merged schedule for every candidate, unlike v6's
   batch materialization or v5x's AVX2 schedule buffer.
3. **Interleave independent encryptions.** V5 performs one round for each of
   two, three, or four candidates before advancing to the next round. These
   streams are independent scalar dependency chains, not OS threads or SIMD
   lanes. They give the processor independent instructions to execute while
   another stream waits for a lookup or dependent calculation. The measured
   configuration uses three streams; the portable default is two.
4. **Reject before the final round.** The fixed plaintext's initial state is
   precomputed, and the target is transformed once into DES's internal form.
   After round 15, one 32-bit half can already be compared with the target.
   Round 16 and the other half comparison run only if that first comparison
   succeeds. V5 does not reconstruct a full ciphertext for every rejected key.
5. **Amortize bookkeeping.** Progress updates and cancellation polling occur
   at pair-block boundaries rather than for each candidate. A scalar remainder
   loop handles candidates left over after the interleaved groups.

This combination explains the design advantage over the other scalar variants:
v1 rebuilds schedules, v2/v3 reuse more work but do not have v5's interleaved
round execution, v4 supplies the pair-schedule foundation but encrypts one
candidate at a time, and v6 adds merged-schedule buffer traffic. The default
DES substitution/permutation tables total only 2 KiB, keeping the lookup
footprint small. The alternative 64 KiB and 256 KiB layouts reduce lookup count
but performed worse for v5 on the tested host.

In the final AVX2 results above, three-stream v5 was the fastest **scalar
variant tested**, at **36.67 million candidates/s with one thread** and
**138.44 million/s with twelve threads**, ahead of v1-v4, v6, and experimental
v5x. The separate alternating stream-count experiment measured a 24.9%
single-thread gain from three streams over two. Four streams did not improve
on three and had a lower multicore median. Additional streams increase code
size and register pressure, so more interleaving is not automatically faster.

These observations apply to the tested CPU, compiler, alphabet, and settings;
they are not a universal ranking or a hardware-counter proof of each effect.
The bitsliced variants are a separate design and can be substantially faster.
See [scalar table comparisons](docs/SCALAR_COMPARISON.md),
[stream-count comparisons](docs/V5_STREAMS.md), and [v5x results](docs/V5X.md).

### Scalar v5 stream count

Configure `-DLMCRACK_V5_STREAMS=3` to run three independent scalar DES
encryptions in flight in v5. Values 2, 3, and 4 are supported; the portable
default remains 2. This changes v5 only and is independent of SIMD selection.
On the measured Core Ultra 5 135U, three streams with default tables improved
single-thread throughput by approximately 25%. Multicore results were noisy;
four streams did not justify replacing three. See
[v5 stream comparison](docs/V5_STREAMS.md) for raw trials and limitations.

With comparisons enabled, `lmcrack_scalar_default` explicitly uses two streams,
while `lmcrack_scalar_stream3` and `lmcrack_scalar_stream4` use three and four.
All three comparison targets force default scalar tables. Example:

```powershell
cmake --build build-avx2 --target lmcrack_scalar_default lmcrack_scalar_stream3 lmcrack_scalar_stream4
./tools/benchmark_v7_comparison.ps1 -BuildDirectory build-avx2 -Versions 5 `
  -Alphabets ABCDEFGHIJKLMNOPQRSTUVWXYZ `
  -Variants lmcrack_scalar_default,lmcrack_scalar_stream3,lmcrack_scalar_stream4
```

### Experimental v5x

Use `-v5x` for three-stream scalar encryption with AVX2 schedule merging.
It requires an AVX2-enabled build and is opt-in; normal v5 is unchanged.
The new mode creates three merged schedules per group using AVX2, then consumes
them in the scalar DES loop. It was slower than three-stream v5 on the measured
host, so it is retained for experimentation rather than recommended as a faster
default. See [v5x implementation and measurements](docs/V5X.md).

### Backend selection

The bitslice implementation has scalar, SSE2, AVX2, AVX-512F, and ARM64 NEON
backends. The build selects one backend at compile time; it does not perform
runtime CPU dispatch. Build the lowest common backend required by the target
machines, or distribute separate binaries for different instruction sets.

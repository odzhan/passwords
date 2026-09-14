# Scalar DES table-layout comparison

Core Ultra 5 135U, Windows, GCC 13.2 Release with LTO, 2026-09-14.
All binaries share compile settings except scalar table definitions. Although
compiled in the AVX2 project, the selected v4/v5/v6 workers use scalar DES.
Default tables occupy 2 KiB; pair tables occupy 64 KiB or 256 KiB.

Correction from subsequent source inspection: v4's main loop hardcodes the
default `des_SPtrans` tables. Its rows compare build configurations, not three
different v4 round-table implementations. The v3 fallback follows the selected
layout, but these seven-character ranges do not use that fallback.

Method: actual executable throughput, synthetic zero hash, seven-character A-Z
search ranges, 1 and 12 threads, three five-second trials per case. Each trial's
last cumulative CLI progress rate is recorded. Layout order rotates per repeat.
No affinity or clock control; multicore trials show appreciable variability.

## Median million candidates per second

| Version | Threads | Default | Pair64 | Pair256 |
| --- | ---: | ---: | ---: | ---: |
| v4 | 1 | 18.55 | 18.98 | 17.87 |
| v4 | 12 | 105.98 | 116.75 | 108.93 |
| v5 | 1 | 29.51 | 22.09 | 24.88 |
| v5 | 12 | 140.62 | 87.52 | 81.08 |
| v6 | 1 | 18.39 | 13.58 | 17.77 |
| v6 | 12 | 106.28 | 66.97 | 61.02 |

## Raw trials

| Version / threads | Default | Pair64 | Pair256 |
| --- | --- | --- | --- |
| v4 / 1 | 19.17, 18.04, 18.55 | 18.98, 18.21, 19.68 | 19.15, 17.85, 17.87 |
| v4 / 12 | 122.62, 104.86, 105.98 | 123.19, 116.75, 109.25 | 124.01, 108.93, 102.96 |
| v5 / 1 | 28.34, 29.51, 29.57 | 22.48, 22.00, 22.09 | 24.88, 25.14, 24.78 |
| v5 / 12 | 150.07, 127.16, 140.62 | 87.52, 87.27, 88.12 | 81.08, 80.16, 82.00 |
| v6 / 1 | 17.03, 18.39, 18.65 | 13.45, 13.68, 13.58 | 17.82, 17.51, 17.77 |
| v6 / 12 | 114.25, 93.85, 106.28 | 74.89, 66.97, 66.83 | 68.84, 61.02, 60.64 |

## Decision

Use v5 with default tables as the scalar optimization baseline. It wins this
matrix at both thread counts. Paired tables reduce lookup count but increase
table footprint and change index arithmetic; the measurements do not isolate
which factor causes the observed slowdown. Do not globally enable paired tables.
V4's differences cannot establish a paired-table benefit; v5's default-table advantage
over paired layouts has non-overlapping ranges here.

Next experiment: compare two, three, and four independent v5 encryptions in
flight with default tables. Inspect register spills and measure both thread
counts before retaining a variant. Keep v1 as the recovery reference. Do not
assume that v6's merged schedule buffer is helpful based on memory contiguity.
This matrix does not isolate schedule-merging time or hardware cache misses.

## Reproduction and validation

Configure `LMCRACK_BUILD_COMPARISONS=ON`; explicitly build
`lmcrack_scalar_default`, `lmcrack_scalar_pair64`, `lmcrack_scalar_pair256`.
Run `tools/benchmark_scalar.ps1 -BuildDirectory <build-directory>`.
The default compiler flags, alphabet, timing, and repetition count should be
held fixed for follow-up comparisons. Other CPUs and alphabets remain untested.

All three binaries passed `tests/integration/scalar_cli_differential.cmake`:
v1/v4/v5/v6 recovered the same known passwords for lengths 1-7, a length
transition, and an uneven three-thread range (27 cases, 108 version recoveries).
This is targeted validation of existing table layouts; exhaustive scalar range
semantics and hardware-counter profiling remain separate work.

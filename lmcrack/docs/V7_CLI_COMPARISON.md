# V7 transpose and lane-scan comparison

Measured 2026-09-14 on Core Ultra 5 135U (12 cores, 14 logical processors),
Windows, GCC 13.2, Release AVX2 with LTO. Three five-second runs per case;
variant order rotates per repetition. Seven-character ranges and synthetic
all-zero targets; rate is the last cumulative CLI progress sample. No affinity,
frequency control, or guaranteed idle machine. Units below: million candidates/s.

All variants use schedule-free DES and staged matching:

- **Before:** reference transpose and reference lane scan.
- **Transpose:** new transpose and reference lane scan.
- **Current:** new transpose and new lane scan.

| Alphabet | Threads | Before median | Transpose median | Current median |
| --- | ---: | ---: | ---: | ---: |
| A-Z | 1 | 14.16 | 32.60 | 46.03 |
| A-Z | 12 | 56.38 | 217.48 | 224.92 |
| Alphanumeric | 1 | 14.89 | 62.34 | 64.63 |
| Alphanumeric | 12 | 57.01 | 201.43 | 194.34 |
| With punctuation | 1 | 12.59 | 50.98 | 56.59 |
| With punctuation | 12 | 61.31 | 204.96 | 212.76 |

Raw trials in execution-repetition order:

| Alphabet / threads | Before trials | Transpose trials | Current trials |
| --- | --- | --- | --- |
| A-Z / 1 | 16.92, 13.04, 14.16 | 32.60, 27.23, 52.58 | 12.48, 46.03, 56.96 |
| A-Z / 12 | 51.38, 56.38, 65.94 | 220.42, 211.08, 217.48 | 224.92, 164.54, 225.05 |
| Alphanumeric / 1 | 14.89, 16.59, 10.73 | 62.34, 63.99, 55.54 | 64.63, 65.34, 60.15 |
| Alphanumeric / 12 | 76.48, 57.01, 49.51 | 238.96, 201.43, 193.51 | 194.34, 201.25, 181.20 |
| Punctuation / 1 | 12.59, 14.82, 12.38 | 54.98, 50.08, 50.98 | 54.38, 56.59, 57.34 |
| Punctuation / 12 | 70.52, 60.45, 61.31 | 209.22, 200.11, 204.96 | 228.53, 191.04, 212.76 |

The transpose improvement is clear across cases. The smaller incremental
lane-scan improvement is not established consistently by this noisy CLI run;
the alphanumeric 12-thread median declined and ranges overlap. Do not interpret
the medians as a universal scaling curve or promise of performance.

The phase profiler measured approximately 151-239 ns for the reference lane
scan and 1.2-1.7 ns for the new scanner with 15 empty masks and one last-lane
match per 16 calls. This synthetic distribution isolates the common empty-mask
path; it is not a complete cracking throughput measure. DES and transpose remain
the dominant measured pipeline phases. Repeat on an idle host with controlled
affinity before making further small performance decisions.

Validation: all 84 tests passed, including exhaustive first-set-bit/tail-boundary
comparisons on scalar, SSE2, and AVX2. AVX-512 compile test passed; no AVX-512 or
NEON execution was performed. The scanner handles an empty mask before storing
it, then checks 64-bit chunks and uses trailing-zero count where supported.
`LMCRACK_REFERENCE_LANE_SCAN` retains the original behavior for A/B testing.

Reproduce using the CMake `LMCRACK_BUILD_COMPARISONS` option and
`tools/benchmark_v7_comparison.ps1` as described in the README. Reference
executables intentionally remain outside the default build.

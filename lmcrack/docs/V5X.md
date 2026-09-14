# v5x: AVX2 schedule merging, three-stream scalar encryption

Select explicitly with `-v5x` in an AVX2-enabled build. v5x is not run by the
default all-version loop and does not replace v5 or occupy version 10.
Builds without AVX2 support reject the selector with an explanation.

Each three-candidate group combines the existing invariant prefix schedule
with three existing character-pair schedules. The helper loads four 256-bit
chunks of the prefix and shares each across three vector OR operations,
producing three contiguous 128-byte schedules in a 384-byte local buffer.
This is merging precomputed schedules, not three fresh DES key expansions.
The three-stream scalar DES loop consumes those schedules without per-round
prefix/pair ORs. A final group of one or two candidates is handled scalarly
with AVX2 schedule merges. The one-character case retains v5's v3 fallback.
Like v5, round 16 executes only after a half-block match.

Schedule generation and encryption alternate per group. This first experiment
does not pipeline the next group's generation during current encryption.
The experimental worker is separate from v5 to preserve its measured baseline;
future fixes to shared legacy enumeration should cover both workers.

## Results

Core Ultra 5 135U, Windows, GCC 13.2 Release/LTO, default scalar tables,
five five-second CLI trials, seven-character A-Z, order alternates, no affinity
or frequency control. The comparison uses v5 with **three streams**, in the
same executable as v5x. Units: million candidates/second.

| Threads | v5 median | v5x median | v5x change |
| --- | ---: | ---: | ---: |
| 1 | 31.55 | 27.73 | -12.1% |
| 12 | 140.29 | 133.38 | -4.9% |

| Threads | v5 raw trials | v5x raw trials |
| --- | --- | --- |
| 1 | 31.09, 31.55, 30.52, 34.39, 34.28 | 28.29, 27.73, 27.35, 27.31, 30.99 |
| 12 | 154.76, 137.78, 133.67, 140.29, 141.09 | 151.91, 143.90, 120.69, 132.95, 133.38 |

The whole-pipeline result does not show a benefit from full schedule
materialization. Multicore ranges overlap, so the precise multicore slowdown
is uncertain. Disassembly confirms YMM `vpor` and `vmovdqu` instructions for
the merges. Additional buffer stores/reloads and register pressure are possible
causes, not established by hardware-counter measurements. Keep v5 as the
recommended implementation on this host. Smaller round-key blocks with
generation interleaved between rounds are a separate future experiment.

## Verification

The full AVX2 build passes 89/89 tests. New tests cover AVX2 schedule output
against scalar ORs for 100 input sets, counts 1-3, offsets 0-7, and untouched
output guards. CLI checks compare recovery to v1 across all pair positions in
ABC/ABCDE alphabets, shortened starting blocks, tails, lengths 1-7, a length
transition, and an uneven multithreaded range. An SSE2-only executable also
builds and rejects `-v5x` as expected. AVX-512 execution and other CPUs remain
unmeasured.

## Reproduce

Configure AVX2 and `-DLMCRACK_V5_STREAMS=3`, build, then run:

```powershell
./tools/benchmark_v7_comparison.ps1 -BuildDirectory build-avx2 -Versions 5 `
  -Alphabets ABCDEFGHIJKLMNOPQRSTUVWXYZ -Variants lmcrack:5,lmcrack:5x `
  -Repetitions 5
```

The shared runner accepts `executable:version` entries to compare selectors
within the same binary. Historical benchmark output is shown above; repeat on
the target machine before drawing conclusions for another compiler or CPU.

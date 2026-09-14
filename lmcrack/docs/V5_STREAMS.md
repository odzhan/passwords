# Scalar v5 stream-count experiment

2026-09-14, Core Ultra 5 135U, Windows, GCC 13.2 Release/LTO, default scalar
tables, seven-character A-Z search, three five-second CLI trials per case.
Executable order rotates; no affinity or fixed CPU frequency. Same benchmark
driver as SCALAR_COMPARISON.md. The selected v5 worker uses scalar DES.

| Streams | 1-thread median M/s | Raw trials | 12-thread median M/s | Raw trials |
| --- | ---: | --- | ---: | --- |
| 2 | 25.65 | 26.71, 25.36, 25.65 | 140.16 | 159.48, 129.42, 140.16 |
| 3 | 32.03 | 32.03, 31.28, 35.46 | 149.33 | 157.06, 149.33, 140.07 |
| 4 | 31.79 | 31.29, 31.79, 34.18 | 129.66 | 153.37, 127.48, 129.66 |

Three streams improved single-thread median throughput by 24.9% and multicore
median by 6.5%. Single-thread ranges do not overlap the two-stream baseline;
multicore ranges overlap, so the smaller multicore gain is not established with
high confidence. Four streams offers no clear single-thread advantage over
three and has a lower multicore median. These are same-run comparisons, not
comparisons with the earlier session's absolute rates.

## Implementation and selection

The two-stream round body remains the reference. Optional three/four-stream
bodies apply each of 15 rounds across all active streams before advancing to
the next round. Round 16 still executes only on a half-block match. A scalar
remainder loop handles 0 through stream-count-minus-one trailing candidates.

`LMCRACK_V5_STREAMS` accepts 2/3/4. Two remains the portable CMake and header
default; the local review build was configured and rebuilt with 3. Four remains
an explicit experiment, not a recommended default. Paired table variants and
other CPUs/compilers have not been benchmarked with the new stream counts.

## Generated code

GNU objdump inspection of the LTO v5 worker:

| Streams | Static instruction lines | RSP-operand lines | Stack-frame subtraction |
| --- | ---: | ---: | ---: |
| 2 | 2407 | 347 | 1208 bytes |
| 3 | 2986 | 380 | 1256 bytes |
| 4 | 3547 | 395 | 1224 bytes |

These cover the entire worker including setup and recovery. Stack references
include required local storage and ABI handling as well as spills; these are
not dynamic instruction counts or isolated spill counts. More streams increase
code size and stack traffic opportunities. They do not prove the cause of the
multicore difference; detailed hardware-counter profiling remains open.

## Validation

Each stream variant passed known scalar recovery comparisons against v1 at
lengths 1-7, a length transition, and an uneven three-thread range. A separate
test checks every pair for alphabets ABC and ABCDE both from the beginning of
the pair block and from the target itself. This exercises stream positions,
odd pair counts, shortened initial blocks, and tail handling (68 cases/variant).

Both integration tests are registered in CTest for the configured production
executable. After selecting three streams, the full suite passed 86/86 tests.
No claims are made about exhaustive legacy scalar range behavior.

# lmcrack Optimization TODO

Baseline measured on an Intel Core Ultra 5 135U using the AVX2 backend:

- DES rounds: approximately 1,474 ns per 256-candidate batch
- Candidate generation and key mapping: approximately 79 ns per batch
- Target matching: approximately 9-14 ns per batch
- Atomic progress update: approximately 4 ns per operation
- Best observed multicore rate: approximately 417 million candidates/second
  with 12 threads

## 1. Optimize the DES Boolean circuit

### Scalar baseline matrix

- [x] Implement opt-in v5x with AVX2 merging of three schedules per group.
- [x] Verify merging, recovery, tails, and rejection in non-AVX2 builds.
- [x] Compare v5x to three-stream v5 in the same executable.
- [ ] Explore smaller round-key blocks to interleave schedule generation with
      encryption without materializing all three full schedules.

v5x passes the 89-test suite but did not improve throughput on this host:
27.73 vs 31.55 M/s single-thread and 133.38 vs 140.29 M/s at twelve threads
(overlapping multicore ranges). It remains opt-in. See [v5x results](docs/V5X.md).

- [x] Build default, 64 KiB, and 256 KiB table variants with identical compiler
      settings and compare v4/v5/v6 at one and twelve threads.
- [x] Validate all three layouts against v1 using known recovery cases.
- [x] Record median and raw trials in [scalar comparison](docs/SCALAR_COMPARISON.md).
- [x] Compare two, three, and four v5 encryption streams using default tables;
      inspect generated stack references and select the measured candidate.
- [ ] Isolate dynamic spill costs and repeat wider-stream tuning on other CPUs.

Three-stream v5 is implemented and selected in the local review build:
32.03 vs 25.65 M/s single-thread (24.9% gain), 149.33 vs 140.16 M/s at twelve
threads (overlapping ranges). Portable default remains two; four is experimental.
All 86 tests pass. See [stream comparison](docs/V5_STREAMS.md).

The winning scalar baseline is v5/default: 29.51 M/s single-thread and
140.62 M/s at twelve threads on this host. No production table default or
scalar worker was changed by this measurement step. Detailed phase costs,
cache counters, and other alphabets/CPUs remain unmeasured.

Validation update (2026-09-14): GCC 13.2 Release AVX2 build completed and
all 80 configured tests passed after rebuilding all targets. AVX-512 was
compile-tested only; NEON was not tested on this host. The experimental
compile-time S-box specialization caused v9 CLI access violations and was
withdrawn. The fused P-permutation implementation remains; its isolated
before/after speedup has not been established.

The standard and select circuit families were compared in earlier profiler
runs on scalar, SSE2, and AVX2. Standard was faster on this host, so the
production family selection remains unchanged. Forced-family preprocessor
options are available for further experiments. These exploratory timings
do not establish performance on other processors.

Current executable throughput, measured with `tools/benchmark_versions.ps1`:
one thread, three five-second trials per version, seven-character candidates,
Core Ultra 5 135U. Values are the last cumulative CLI rate in each trial;
no CPU affinity was applied. These are current rates, not measured speedups.
v1-v8 use A-Z; v9 uses digits/A-Z; v11 uses its printable alphabet.

| Version | Median million candidates/s | Trial minimum | Trial maximum |
| --- | ---: | ---: | ---: |
| v1 | 5.38 | 5.15 | 6.56 |
| v2 | 6.72 | 6.71 | 6.87 |
| v3 | 16.72 | 16.57 | 17.38 |
| v4 | 19.28 | 19.16 | 19.78 |
| v5 | 30.11 | 29.52 | 30.21 |
| v6 | 18.63 | 18.60 | 18.82 |
| v7 | 18.86 | 18.79 | 19.10 |
| v8 | 166.17 | 161.31 | 166.35 |
| v9 | 162.41 | 159.99 | 165.14 |
| v11 | 155.71 | 155.32 | 156.20 |

v10 is unassigned. The direct phase profiles, backend coverage, and
before/after acceptance work below remain open.

- [ ] Establish separate, directly timed baselines for v1 through v11; do not
      infer their throughput from the CLI's one-second status interval.
- [ ] Profile v1's per-candidate key-schedule construction and keep it as the
      correctness/reference baseline.
- [ ] Profile v2's precomputed per-character schedules, including table lookup
      and cache behavior.
- [ ] Profile v3's incremental schedule updates and identify redundant updates
      across radix carries.
- [ ] Profile v4's two-character schedule-pair tables and compare the 64 KiB,
      256 KiB, and default table configurations.
- [ ] Profile v5's two independent encryptions in flight and tune interleaving
      for instruction-level parallelism.
- [ ] Profile v6's contiguous batch-key materialization and quantify whether
      memory traffic outweighs scheduling savings.
- [ ] Benchmark both existing Openwall S-box circuit variants on every supported
      SIMD backend.
- [ ] Inspect generated assembly for register spills in the fully unrolled DES
      rounds.
- [ ] Record instruction counts, cycles per batch, and candidates per second for
      each S-box/backend combination.
- [x] Fuse the DES P permutation into the S-box output assignments.
- [ ] Eliminate or reduce the `substituted[32]`, `output[32]`, and round-local
      temporary arrays where this improves generated code.
- [ ] Investigate separately tuned scalar, SSE2, AVX2, AVX-512, and NEON Boolean
      circuits.
- [x] Verify all DES, bitslice, v8, v9, v11, and integration tests after each
      circuit change.
- [ ] Retain a circuit change only when repeated benchmarks show a meaningful
      improvement without regressions on other supported backends.

### v7 general bitslice optimization

#### Baseline and instrumentation

- [x] Add a direct v7 benchmark that does not use the CLI's one-second status
      interval.

`v7_profile [iterations]` now directly measures generation, transpose, schedule,
both DES paths, both matchers, and original/current combined pipelines. Default:
20,000 batches, five repetitions, alternating phase order, warmup, three
alphabets. It checks identical encrypted states for 16 fixtures per alphabet,
including a partial tail. This is a limited differential check, not exhaustive
worker/range validation. The benchmark omits worker atomics and thread startup.

GCC 13.2 Release AVX2, Core Ultra 5 135U, no affinity, 2026-09-14:

| Alphabet | Original M/s | Current M/s | Speedup |
| --- | ---: | ---: | ---: |
| A-Z | 18.39 | 20.10 | 1.093x |
| 0-9, A-Z | 17.17 | 19.12 | 1.114x |
| punctuation, digits, A-Z | 16.41 | 18.09 | 1.103x |

Transpose costs 10.43-11.47 microseconds/batch, versus 0.51-0.54 for generation
and 1.19-1.40 for schedule-free DES. Optimize transpose next. These measurements
support the combined v7 change on this host, not an isolated permutation-fusion
gain or a guarantee on other backends. The added CTest smoke test passes.
- [ ] Record baseline throughput for scalar, SSE2, AVX2, AVX-512, and NEON where
      representative hardware is available.
- [ ] Benchmark several alphabet sizes, password lengths, aligned full batches,
      partial batches, and range boundaries.
- [ ] Measure candidate generation, password transposition, key scheduling, DES,
      target matching, progress accounting, and stop polling independently.

#### Candidate generation

- [ ] Inspect `bs_candidate_next` for division, modulo, avoidable branches, and
      repeated work in the steady-state loop.
- [ ] Replace scalar candidate reconstruction with incremental counters where it
      produces a measured improvement.
- [ ] Special-case full SIMD batches while preserving correct partial-tail
      behavior.
- [ ] Verify carries across every digit and password-length transition.

#### Password-to-key-plane conversion

- [x] Replace repeated bit-by-bit alphabet lookups with an eight-byte bitwise
      transpose, retaining `bs_transpose_passwords_reference` for comparison.
- [x] Differential-test every batch size, mixed lengths 0-7, arbitrary byte
      values, and zero-filled unused lanes against the reference.

Transpose update (2026-09-14): full rebuilt suite passes 81/81. Five-repeat
AVX2 same-binary comparisons in `v7_profile 20000` show:

| Alphabet | Before transpose change M/s | After M/s | Speedup |
| --- | ---: | ---: | ---: |
| A-Z | 17.59 | 66.16 | 3.762x |
| Alphanumeric | 17.06 | 64.99 | 3.811x |
| With punctuation | 17.37 | 65.59 | 3.776x |

Both pipelines use schedule-free DES and staged matching; only the transpose
differs. Transpose itself fell from 11.5-11.9 to 1.5-1.6 microseconds/batch.
These are harness rates excluding worker atomics, not CLI rates. The fully
original scheduled pipeline is still reported separately. Compiler/CPU match
the earlier profile; no affinity was applied. Other hardware remains unmeasured.

- [ ] Measure `bs_transpose_passwords` separately for common alphabet sizes.
- [ ] Inspect generated assembly for scalar loops, spills, and redundant loads.
- [ ] Evaluate direct construction of key planes from bitsliced alphabet indexes,
      avoiding intermediate candidate materialization.
- [ ] Retain the generic transpose fallback for alphabets that do not benefit
      from specialized mapping.

#### Key-schedule removal

- [x] Replace v7's per-batch 16-by-48-plane key-schedule construction with the
      shared schedule-free round-key plane mapping.
- [ ] Confirm that arbitrary alphabet bytes produce the same 56 canonical LM key
      planes expected by the schedule-free DES implementation.
- [ ] Compare schedule-free v7 against the original scheduled implementation
      using identical candidate batches.
- [ ] Inspect whether removing the schedule reduces stack usage, memory traffic,
      and register spills.

#### DES round path

- [ ] Apply the selected S-box circuit independently to v7 and benchmark it.
- [ ] Fuse the DES P permutation into S-box output placement in the v7 hot path.
- [ ] Inspect all 16 generated rounds for spills and unintended loop or switch
      dispatch.
- [ ] Compare fully unrolled, partially unrolled, and looped variants if register
      pressure remains high.

#### Target matching

- [x] Fast-reject empty match masks and scan nonempty masks in 64-bit chunks.
- [x] Differential-test the scanner for every first bit and tail boundary on
      scalar, SSE2, and AVX2; compile-test AVX-512.
- [x] Compare actual v7 CLI throughput before/after transpose and lane scanning
      across three alphabets, one thread, and twelve threads.

See [V7 CLI comparison](docs/V7_CLI_COMPARISON.md) for raw trials, medians, and
limitations. All 84 tests pass. Transpose improvement is confirmed; the small
incremental scanner gain remains inconclusive in noisy multithreaded CLI trials.

- [x] Replace v7's full final permutation and 64-plane comparison with prepared,
      staged target matching.
- [ ] Order comparison stages to reject non-matches with minimal work.
- [ ] Verify matching for full batches, partial batches, and every valid lane.
- [ ] Benchmark target matching using both non-matching and matching batches.

#### Progress and cancellation

- [ ] Accumulate v7 progress locally and publish it at a controlled interval.
- [ ] Remove the per-batch atomic decrement when counter-local range state can
      determine completion.
- [ ] Choose a stop-poll interval that balances throughput and cancellation
      latency.
- [ ] Check shared worker state for false sharing.

#### Correctness and compatibility

- [ ] Differential-test optimized v7 against the original implementation for
      randomized alphabets, ranges, lengths, and target hashes.
- [ ] Test duplicate, reordered, punctuation, boundary-byte, and maximum-length
      alphabets accepted by the CLI contract.
- [ ] Verify candidate ordering and inclusive start/end range semantics remain
      unchanged.
- [ ] Run the complete scalar, SSE2, AVX2, AVX-512 compile, worker, differential,
      and CLI test matrix.
- [ ] Run sanitizer builds for the generic candidate and transpose paths.

#### Performance acceptance

- [ ] Run repeated before/after benchmarks with identical compiler, affinity,
      backend, alphabet, and range settings.
- [ ] Report median, best, variability, and candidates per cycle.
- [ ] Reject or revise changes that regress any important custom-alphabet case.
- [ ] Document the final v7 improvement and remaining bottleneck percentages.

## 2. Add runtime SIMD dispatch

- [ ] Define the minimum supported CPU feature checks for SSE2, AVX2, and
      AVX-512, including operating-system vector-state support.
- [ ] Compile backend-specific implementations into one executable without
      leaking backend-specific compiler flags into generic code.
- [ ] Select the fastest supported backend during program startup.
- [ ] Provide a command-line or environment override for testing and diagnosing
      backend selection.
- [ ] Print the selected backend in diagnostic or benchmark output.
- [ ] Preserve a portable scalar fallback.
- [ ] Benchmark AVX-512 against AVX2 under sustained load to account for possible
      frequency throttling.
- [ ] Test the dispatch logic on machines with different feature sets.

## 3. Make thread selection topology-aware

- [ ] Measure scaling repeatedly from one thread through every available logical
      processor.
- [ ] Compare physical-core-only execution with SMT-enabled execution.
- [ ] Measure the effect of processor affinity and hybrid performance/efficiency
      core placement.
- [ ] Replace the default based solely on `hardware_concurrency()` with a
      topology-aware policy or a short startup calibration.
- [ ] Continue to honor an explicit user-supplied thread count.
- [ ] Avoid creating more workers than the candidate range can use efficiently.
- [ ] Document how automatic thread selection behaves on conventional, SMT, and
      hybrid CPUs.

## 4. Reduce hot-loop bookkeeping

- [ ] Accumulate completed candidates in a thread-local counter.
- [ ] Publish progress periodically instead of performing an atomic addition
      after every SIMD batch.
- [ ] Remove the per-batch atomic decrement of `total_cbn` and use counter-local
      remaining-range state where possible.
- [ ] Keep stop polling responsive while reducing synchronization traffic.
- [ ] Check cache-line placement of shared atomics to prevent false sharing.
- [ ] Verify accurate progress, range completion, early stopping, and password
      recovery with multiple threads.
- [ ] Benchmark the change independently; treat it as a small optimization unless
      measurements demonstrate otherwise.

## 5. Optimize v11 radix-69 mapping

- [ ] Measure v11 counter advancement and key-plane mapping separately from DES.
- [ ] Derive a minimized Boolean circuit that maps radix-69 digits directly to
      printable LM character bits.
- [ ] Compare the minimized circuit with the current five-threshold/category
      implementation.
- [ ] Look for common subexpressions shared across comparisons and output bits.
- [ ] Evaluate lookup-assisted or generated circuits only if they remain
      constant-time across bitslice lanes and improve generated code.
- [ ] Inspect register pressure and spills after integrating the new mapping.
- [ ] Differential-test every alphabet symbol, digit carry, length transition,
      partial batch, and arbitrary range boundary.
- [ ] Keep the documented v11 alphabet and candidate ordering unchanged.

## 6. Improve benchmark methodology

- [ ] Replace costs derived by subtracting independently timed loops with direct
      phase measurements.
- [ ] Run multiple repetitions and report the median, minimum, and variability.
- [ ] Increase measurement duration enough to reduce timer and scheduling noise.
- [ ] Add optional thread affinity and record the processors used.
- [ ] Report cycles per batch in addition to nanoseconds and candidates per
      second.
- [ ] Add hardware-counter support for instructions, branches, cache misses,
      frequency, and vector-related throttling where available.
- [ ] Benchmark v7, v8, v9, and v11 directly with comparable ranges and targets.
- [ ] Benchmark scalar, SSE2, AVX2, AVX-512, and NEON builds on representative
      hardware.
- [ ] Record compiler, compiler flags, CPU model, backend, thread count, warmup,
      duration, and operating-system details with every result.
- [ ] Establish a reproducible baseline and an acceptance threshold before making
      optimization changes.
- [ ] Add benchmark result storage or export suitable for comparing revisions.

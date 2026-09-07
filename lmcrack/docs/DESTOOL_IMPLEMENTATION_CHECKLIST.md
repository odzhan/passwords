# destool Implementation Checklist

## Goal

Build a separate `destool` executable that searches a frozen character-key
space for a DES key matching one known 8-byte plaintext/ciphertext pair. Reuse
the schedule-free bitslice DES implementation from lmcrack while keeping
lmcrack behavior and performance unchanged.

## Fixed alphabets

| ID | Description | Canonical byte order | Radix |
|---:|---|---|---:|
| 1 | All byte values | `00` through `FF` | 256 |
| 2 | Decimal digits | `0123456789` | 10 |
| 3 | Uppercase ASCII | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 26 |
| 4 | Lowercase ASCII | `abcdefghijklmnopqrstuvwxyz` | 26 |
| 5 | Digits and uppercase ASCII | `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ` | 36 |
| 6 | Digits and lowercase ASCII | `0123456789abcdefghijklmnopqrstuvwxyz` | 36 |
| 7 | Digits, lowercase, and uppercase ASCII | `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ` | 62 |

## Contract and architecture

- [x] 1. Freeze the command-line and key-format contract
  - Use `destool <plaintext-hex> <ciphertext-hex> -a <1-7> -l <1-7>`.
  - Keep `-t <threads>` for the worker-thread count.
  - Require plaintext and ciphertext to be exactly 16 hexadecimal characters,
    representing one 8-byte DES block in external byte order.
  - Define candidates as 1 through 7 raw bytes, zero-padded to seven bytes and
    expanded with the existing LM 7-byte-to-DES-key mapping.
  - Require an explicit key length to avoid ambiguity when alphabet 1 contains
    `00`.
  - Define position zero as the fastest-changing candidate digit.
  - Define output formatting: printable keys as text plus hex; binary keys as
    hex so embedded zero and non-printable bytes are preserved.
  - Explicitly reject literal eight-byte DES-key mode in the first release;
    DES parity makes that a distinct search contract.

### Step 1 completion record

- The frozen interface, exact-length enumeration, binary range encoding,
  LM-style key expansion, output representation, and exit statuses are defined
  in `docs/DESTOOL_CONTRACT.md`.

- [x] 2. Define reusable destool job and result types
  - Store the plaintext, ciphertext, alphabet ID, exact key length, absolute
    start/end combination numbers, thread count, progress, stop, and found
    state.
  - Keep shared state atomically safe and use half-open worker ranges.
  - Represent recovered keys as bytes rather than C strings.
  - Add checked radix-power and total-candidate calculations with overflow
    validation.

### Step 2 completion record

- Added `src/destool/destool_types.h` with search, worker, shared-state, result,
  checked-power, and balanced half-open partitioning primitives.
- Added `destool_types_test`; the focused Release test passes.

## Generic bitslice DES extraction

- [x] 3. Generalize plaintext block preparation
  - Extract a helper that broadcasts any 8-byte plaintext into bitslice planes
    and applies the DES initial permutation once per job.
  - Retain the existing LM fixed-plaintext wrapper for lmcrack compatibility.
  - Test zero, all-one, alternating-bit, and standard DES plaintext blocks.

### Step 3 completion record

- Added `bs_prepare_plaintext_state()` for arbitrary eight-byte blocks and
  retained `bs_init_lm_plaintext_state()` as a compatibility wrapper.
- Extended `bitslice_block_test` with zero, all-one, alternating, standard DES,
  LM, equivalence, and invalid-argument cases; the Release test passes.

- [x] 4. Generalize ciphertext target preparation and matching
  - Pre-permute an arbitrary target ciphertext into the representation used
    after the DES rounds.
  - Reuse staged early rejection where profitable.
  - Mask invalid SIMD tail lanes before reporting a match.
  - Retain compatibility wrappers used by v8 and v9.
  - Differentially test generic matching against scalar DES output.

### Step 4 completion record

- Added the neutral `bitslice_target.h` interface for arbitrary ciphertext
  preparation, full matching, staged early rejection, and tail masking.
- Redirected the v9 fixed-target compatibility interface through the neutral
  API and added a scalar-DES differential test using a non-LM plaintext.
- The new target test plus the existing v8 target and v9 worker tests pass.

- [x] 5. Expose a neutral schedule-free DES interface
  - Remove remaining v8-specific names from the reusable internal interface,
    retaining wrappers so v8/v9 generated behavior remains unchanged.
  - Accept 56 LM-style key-material planes and an arbitrary prepared block.
  - Keep all round-key plane indexes compile-time constant.
  - Verify the compiler still inlines the hot path without adding a materialized
    per-candidate key schedule.

### Step 5 completion record

- Moved the schedule-free round-key map and unrolled DES rounds into the
  neutral `bitslice_fixed_des.h`; v8 and v9 retain compatibility wrappers.
- Added `bs_fixed_encrypt_state()` for arbitrary prepared plaintext state and
  56 key-material planes.
- Existing fixed-DES, v8 direct-DES/target/worker, v9 worker, and generic target
  tests pass. Optimized AVX2 assembly contains no calls to the wrapper layers.

## Fixed-alphabet candidate generation

- [x] 6. Implement and test canonical combination-number mappings
  - Implement radix 10, 26, 36, 62, and 256 mappings for exact lengths 1–7.
  - Support conversion in both directions for range partitioning and recovery.
  - Test zero, final value, every carry boundary, non-aligned starts, and
    round trips for every alphabet and length.

### Step 6 completion record

- Added `destool_alphabet.h` with all seven frozen alphabets, radix lookup,
  byte/digit conversion, exact-length sizing, and bidirectional CBN mapping.
- Exhaustive symbol and all-length boundary/carry/round-trip tests pass.

- [x] 7. Implement specialized bitsliced counters
  - Use four planes per digit for radix 10, five for radix 26, six for radix
    36/62, and eight for radix 256.
  - Initialize all SIMD lanes from an arbitrary absolute start without
    constructing per-lane key strings.
  - Advance batches with plane-level arithmetic and radix reduction.
  - Support partial final batches and exact thread-range boundaries.
  - Reuse counter implementations between alphabet pairs that share a radix.

### Step 7 completion record

- Added the shared templated radix 10/26/36/62/256 bitslice counter with
  four/five/six/eight digit planes, arbitrary starts, plane-level advance,
  shared-radix reuse, and exact tail handling.
- Boundary, multi-batch, non-aligned, final-tail, and all-alphabet/length tests
  pass in `destool_bitslice_counter_test`.

- [x] 8. Convert candidate digits directly to key-material planes
  - Map alphabet 1 values directly to byte planes.
  - Add fixed Boolean/arithmetic mappings for digits, uppercase, lowercase,
    digit-uppercase, digit-lowercase, and digit-lowercase-uppercase alphabets.
  - Zero all positions beyond the requested exact key length.
  - Avoid per-lane byte conversion in the steady-state loop.
  - Exhaustively test every symbol, byte bit, character position, and available
    SIMD backend.

### Step 8 completion record

- Added direct Boolean/arithmetic mappings for raw bytes, digits, uppercase,
  lowercase, radix-36 digit/case pairs, and radix-62 digit/lower/upper keys.
- Invalid lanes and positions beyond the exact length are zeroed without
  per-lane conversion in the steady-state path.
- Default, scalar, SSE2, and AVX2 runtime tests pass; AVX-512 compiles. NEON is
  registered for runtime validation on ARM64.

- [x] 9. Add generator differential tests
  - Compare complete generated batches with a scalar reference enumerator.
  - Cover every alphabet, length, carry boundary, arbitrary worker start, full
    batch, partial batch, and final candidate.
  - Confirm recovered lane numbers map back to the exact canonical key bytes.

### Step 9 completion record

- Added scalar differential coverage for every alphabet and key length,
  arbitrary starts, carry boundaries, full and partial SIMD batches, final
  candidates, and recovered-lane-to-key mapping.
- The focused Release generator differential test passes.

## Worker and command-line tool

- [x] 10. Implement the destool bitslice worker
  - Prepare the plaintext and target once per worker job.
  - Generate candidate key planes, execute schedule-free DES, and apply staged
    target matching.
  - Publish the first recovered key atomically and stop peer workers.
  - Update progress by the exact number of valid candidate lanes.
  - Preserve correct behavior for ranges smaller than one SIMD batch.

### Step 10 completion record

- Added the generic destool worker with once-per-job plaintext/target setup,
  direct key-plane generation, schedule-free DES, staged matching, atomic
  result publication, exact progress accounting, and peer cancellation.
- Worker tests pass for first, middle, last, and partial-tail matches, raw-byte
  keys, exhaustion, and invalid jobs.

- [x] 11. Implement the `destool` executable
  - [x] 11.1 Add standalone CLI option and value types
    - Keep all destool command-line state separate from lmcrack globals.
    - Represent the two block arguments, required alphabet and length, optional
      thread count, and optional inclusive start/end keys.
  - [x] 11.2 Implement strict hexadecimal and unsigned-integer parsers
    - Require plaintext and ciphertext to contain exactly 16 hexadecimal
      characters.
    - Require range keys to contain exactly two hexadecimal characters per key
      byte, preserving zero and high-bit bytes.
    - Reject signs, whitespace, trailing characters, overflow, and zero thread
      counts.
  - [x] 11.3 Parse the command line and provide help
    - Accept the frozen positional arguments and `-a`, `-l`, `-t`, `-s`, and
      `-e` options in documented form.
    - Detect missing values, duplicate/conflicting options, unknown options,
      and unexpected positional arguments.
    - Add concise usage text, alphabet descriptions, key-range semantics, and
      exit-status documentation.
  - [x] 11.4 Validate and normalize the search specification
    - Validate alphabet ID 1-7, key length 1-7, and thread count 1-32.
    - Validate optional range endpoints against the selected alphabet and exact
      key length.
    - Convert the inclusive CLI range into the worker's half-open CBN range,
      reject reversed ranges, and clamp the active worker count to non-empty
      partitions.
  - [x] 11.5 Add backend and key-format display helpers
    - Report the compiled scalar, SSE2, AVX2, AVX-512, or NEON backend.
    - Format recovered material as exact hexadecimal plus an escaped text form
      that cannot hide embedded zero, control, quote, or high-bit bytes.
  - [x] 11.6 Add the multithreaded search coordinator
    - Initialize the bitslice implementation, partition the half-open range,
      launch one worker per non-empty partition, and join every worker.
    - Convert atomic shared state into a stable final result while preserving
      found, exhausted, and internal-failure outcomes.
  - [x] 11.7 Add periodic progress reporting
    - Print selected alphabet, exact key length, candidate count, active thread
      count, and backend before the search.
    - During longer searches, report exact tested count, candidates per second,
      completion percentage, and ETA without materially burdening the hot path.
    - Print a final progress summary for short searches that finish before the
      first periodic update.
  - [x] 11.8 Implement final result output and process exit statuses
    - Print the recovered key in hexadecimal and escaped text on success.
    - Clearly distinguish exhausted and internal-failure results.
    - Return 0 for found, 1 for exhausted, 2 for invalid input, and 3 for an
      internal failure.
  - [x] 11.9 Add focused CLI unit and integration tests
    - Unit-test parsers, normalization, backend naming, and binary-safe key
      formatting.
    - Exercise help, malformed inputs, known recovery, exhaustion, optional
      ranges, and multithreaded uneven partitions through the executable.
  - [x] 11.10 Run the focused Release validation and record completion
    - Build `destool` with the current configured backend.
    - Run all Step 11 unit/integration tests and the existing destool worker
      tests.
    - Mark parent Step 11 complete only after every 11.x checkbox passes.

### Step 11 completion record

- Added the independent `destool` CLI, strict parsers and validation, inclusive
  key-range normalization, backend/key display helpers, multithreaded search
  coordination, low-overhead progress reporting, and documented exit statuses.
- Added parser/formatting, runner, and executable integration tests covering
  help, recovery, exhaustion, exact ranges, malformed input, and uneven worker
  partitions.
- The focused Release validation passed all 9 destool tests.

- [x] 12. Integrate destool into the build system
  - Add the executable through CMake and link the shared internal headers and
    threading dependency.
  - Apply the same scalar, SSE2, AVX2, AVX-512, NEON, LTO, native-CPU, and
    MinGW stack-realignment rules as lmcrack.
  - Add destool targets to sanitizer builds where supported.
  - Update the GNU and Windows Makefiles or explicitly document CMake as the
    only supported destool build path.
  - Add destool build and usage examples to `README.md`.

### Step 12 completion record

- Added the `destool` executable to CMake with the shared internal include
  paths and threading dependency.
- Centralized the selected primary bitslice backend across lmcrack, destool,
  and the profiling tool. Scalar, SSE2, AVX2, AVX-512, and NEON selections now
  apply consistently; MinGW AVX builds retain stack realignment.
- Added destool to Release LTO, native-CPU tuning, and supported sanitizer
  targets. CMake is explicitly documented as the supported destool build path.
- Scalar, SSE2, and AVX2 recovery builds passed; AVX-512 compiled. Optimized
  AVX2 commands contain `-mavx2`, `-mstackrealign`, and LTO switches.

## Correctness and platform validation

- [x] 13. Add known-answer and recovery tests
  - Validate generic encryption with published DES known-answer vectors.
  - Generate keys from each frozen alphabet and recover first, middle, and
    final candidates.
  - Test plaintext/ciphertext containing zero and high-bit bytes.
  - Test exact exhaustion when no key exists in the selected space.
  - Test one thread and uneven multithread partitions.
  - Test malformed hex, invalid alphabet IDs, invalid lengths, reversed ranges,
    and out-of-alphabet range endpoints.

### Step 13 completion record

- Added the canonical DES known-answer vector for plaintext
  `0123456789ABCDEF`, DES key `133457799BBCDFF1`, and ciphertext
  `85E813540F0AB405`, searched through its equivalent seven-byte material.
- Added recovery tests for the first, middle, and last exact-length candidates
  in every frozen alphabet, including zero/high-bit plaintext and ciphertext,
  single-thread operation, and uneven three/seven-thread partitions.
- Added exact exhaustion and expanded malformed CLI coverage for blocks,
  alphabet IDs, lengths, thread counts, ranges, missing/extra arguments, and
  unknown options.
- Corrected the CMake test helper so assertion-based checks remain active in
  optimized Release builds. All focused Step 13 tests pass with assertions on.

- [x] 14. Differentially validate against a scalar DES reference
  - Compare bitslice encryption and matching with scalar DES for randomized
    plaintexts and candidate keys from every alphabet.
  - Compare recovered results and exact progress counts.
  - Confirm lmcrack v1–v9 tests remain unchanged and passing.

### Step 14 completion record

- Added deterministic randomized differential coverage for all seven
  alphabets and lengths 1-7, including arbitrary plaintexts, nonzero starts,
  full/partial SIMD batches, and every ciphertext byte in every valid lane.
- Compared randomized bitslice output directly with the independent scalar DES
  implementation and verified recovered material plus exact batch-granular
  progress counts across SIMD boundaries.
- The complete optimized Release suite passes 71/71 tests with assertions
  active. Separate command-line smoke tests confirm lmcrack v1 through v9 each
  recover the expected password.

- [ ] 15. Validate every supported backend
  - [x] 15.1 Scalar runtime.
  - [x] 15.2 SSE2 runtime on x86/x86-64.
  - [x] 15.3 AVX2 runtime on supported x86-64 hardware.
  - [x] 15.4 AVX-512 compile validation and runtime where available.
  - [ ] 15.5 ARM64 NEON compile validation and runtime on ARM64 hardware.
    - [x] ARM64 NEON cross-compile validation.
    - [ ] ARM64 NEON runtime validation on ARM64 hardware.
  - Confirm forced-scalar builds work on ARM64 without selecting NEON-only
    intrinsics.

### Step 15 partial completion record

- Added full generator, target, worker, recovery, and randomized differential
  coverage for each backend, beyond the existing counter/key-plane tests.
- Scalar, SSE2, and AVX2 each pass seven focused backend tests; the expanded
  Release suite passes 86/86 tests.
- Full-path AVX-512 sources and the destool executable compile successfully.
  Runtime was skipped because this host reports no AVX-512F support.
- Destool main, generator, worker, and randomized differential sources
  cross-compile for ARM64 NEON with Clang/MSVC. The ARM64 forced-scalar main
  also cross-compiles, confirming it does not select NEON-only intrinsics.
- Step 15 remains open solely for execution of the registered NEON tests on an
  ARM64 host; `./arm64.sh` builds and runs that suite.

## Performance and release completion

- [x] 16. Profile and tune the hot path
  - Measure counter advancement, alphabet mapping, DES rounds, target matching,
    progress accounting, and worker synchronization independently.
  - Inspect optimized assembly for spills, scalar per-lane loops, missed
    inlining, and avoidable key-schedule work.
  - Compare exact-length radix 36 performance with lmcrack v9 to detect reuse
    regressions.

### Step 16 completion record

- Added `destool_profile`, which independently measures bitsliced counter
  advancement, alphabet mapping, DES rounds, staged target matching, atomic
  progress updates, stop polling, and the combined hot path. It reports the
  equivalent v9 radix-36 generator phases in the same process.
- AVX2 profiling identified generic radix-36 alphabet mapping as the only
  material reuse overhead. A fixed Boolean alphabet-5 mapping reduced destool
  counting-plus-mapping from roughly 170-180 ns/batch to roughly 85-100
  ns/batch, close to v9's roughly 70-85 ns/batch. Mapping differential tests
  pass after the change.
- DES remains the dominant cost at roughly 1.4-1.9 microseconds/batch on this
  host; staged matching is roughly 9-12 ns, atomic progress roughly 4-5 ns,
  and stop polling below 1 ns.
- A 60,466,176-candidate single-thread radix-36 run measured 133.62M/s for
  destool and 59.47M/s for lmcrack v9 on this host, showing no practical reuse
  regression.
- The optimized AVX2 assembly probe has no scalar division, per-candidate
  conversion, key-schedule, CBN-recovery, or counter-reload calls in the
  steady-state path. It does expose expected DES register-pressure spills and
  runtime S-box dispatch. A forced-inlining experiment improved isolated DES
  time but caused intermittent MinGW AVX stack faults, so it was reverted.
- The complete optimized Release suite passes 86/86 after tuning.

- [ ] 17. Add a repeatable benchmark mode or benchmark driver
  - Use a fixed duration, warm-up period, thread count, plaintext/ciphertext,
    alphabet, and key length.
  - Prevent early target matches from shortening a benchmark.
  - Report candidates per second and total candidates for each backend.
  - Record representative single-thread and multicore results.

- [ ] 18. Final documentation and cleanup
  - Document the LM-style key expansion and explicitly distinguish it from a
    literal eight-byte DES key search.
  - Document alphabet ordering, binary-key output, practical key-space sizes,
    backend selection, and recommended compiler switches.
  - Remove temporary instrumentation and dead experimental paths.
  - Run the complete Release suite with scalar, native SIMD runtime tests, and
    cross-platform compile checks.
  - Record final validation results in this checklist.

## Subsequent lmcrack v11 extension

- Added lmcrack v11 without changing the existing v8 or v9 command-line
  contracts. V10 remains unassigned.
- V11 freezes a 69-character printable LM alphabet in digits, uppercase,
  space, then punctuation order. The complete contract and key-space sizes are
  documented in `docs/LMCRACK_V11.md`.
- Added a radix-69 bitsliced counter, direct printable-ASCII key-plane mapping,
  schedule-free worker, CLI selection, and scalar/SSE2/AVX2 tests.
- The complete AVX2 Release suite passes 97/97 tests. V11's AVX-512 sources
  compile successfully, and its NEON tests are registered for ARM64 execution.

# iris benchmarks

The harness behind the README's performance table. Its own SwiftPM package, outside the root package graph, so the published `iris` package keeps zero dependencies. Build and run from this directory.

## Methodology

Numbers were recorded on an Apple M4 (4P+6E), 24 GiB, macOS 27, Swift 6.2.4, release build. Absolutes are host-relative; the ratios and stability claims are the portable part.

The buffer is deterministic from its seed: 3:1 pattern to random — three consecutive words from a cycling 12-word real-function template (each verified against llvm-mc), then one SplitMix64 word. The blend decodes ≈85% defined, and the random quarter exercises undefined and exotic paths. Features `.arm64e`, default seed `0xc0ffee0015bad`.

Timing is 1 unrecorded warmup plus N recorded runs (`ContinuousClock`), reporting the median with spread = (max − min) / median. Results fold into an opaque sink so the optimizer cannot delete the work. The main table uses a 256 MiB buffer, 9 runs, 10^7 lookups; the memory high-water figure is a single-run peak-RSS delta, a ceiling, not a byte-exact size.

`bulk-parallel` reads 240–360M words/s across runs of the same binary, so quote it as an order of magnitude. `bulk-single`, `tier0-latency`, `session-lookup`, `real-listing` and the Capstone rows hold within ~5%. The structural rows are counts, identical every run.

Separately built binaries carry different code layout and that bias does not average out, so comparing anything under ~5% needs both arms in one process. Throughput is also sensitive to buffer size beyond cache effects, since the parallel modes allocate per-chunk storage concurrently — quote the buffer size with any number.

## Reproduce

```sh
cd Benchmarks
swift run -c release iris-bench                 # the full battery (README numbers)
swift run -c release iris-bench bulk --mib 64   # one mode, custom buffer
swift run -c release iris-bench --json          # machine-readable results
```

Modes: `all` (default) · `memory` · `bulk` · `parallel` · `tier0` · `lookup` · `session` · `walk` · `text` · `real` · `compare` · `view-experiment` · `smoke`. Options: `--runs N` · `--mib N` · `--seed VALUE` · `--jobs N` · `--lookups N` · `--baseline FILE` · `--binary PATH` · `--deadline SECONDS` · `--json`.

Always run release; debug numbers are meaningless and the tool warns.

## Recorded run

Apple M4 (4P+6E), 24 GiB, macOS 27.0, release build, 256 MiB buffer, medians over 9 runs.

| metric | median | spread |
|---|---|---|
| `bulk-single` | 54,502,291 words/s | 5.8% |
| `bulk-parallel` | 302,736,513 words/s | 38.1% |
| `tier0-latency` | 36.59 ns/op | 4.9% |
| `lookup-view` | 44.63 ns/op | 5.1% |
| `lookup-raw` | 5.07 ns/op | 12.7% |
| `session-lookup` | 12.27 ns/op | 2.7% |
| `session-walk` | 2.25 ns/elem | 2.1% |
| `walk-record` | 1.14 ns/elem | 5.7% |
| `text-throughput` | 6,360,819 instr/s | 17.7% |

Over real `__TEXT,__text` (`dyld`, `swift`, `git`, `zsh`, `ls` — 296,057 instructions):

| metric | median | spread |
|---|---|---|
| `real-bulk` | 58,651,757 words/s | 15.6% |
| `real-listing` | 30,864,992 instr/s | 4.9% |
| `real-text-each` | 19,970,903 instr/s | 3.3% |
| `real-semantics` | 179,668,915 instr/s | 18.9% |
| `real-operands-per-word` | 2.13 | structural |
| `real-retained-bytes-per-word` | 118.17 | structural |
| `real-listing-bytes-per-word` | 15.51 | structural |

`real-retained-bytes-per-word` is the 64-byte record stride plus the operand buffer's 9/4-per-word reserve, and `real-operands-per-word` is what that reserve is sized against. Measuring either on the synthetic buffer reports the reserve as waste, since that buffer's operand density is nowhere near real code's.

## The regression smoke

Nightly CI runs `iris-bench smoke --json --baseline baseline.json`, a short configuration (64 MiB, 3 runs, 10^6 lookups) producing the full metric set.

`baseline.json` gates one metric, bulk-single throughput, failing when the median falls below baseline×(1−0.35) — a canary for a ~2× or worse regression. The floor is stale and sits far below current throughput; re-record it from a Nightly run on that host class, which a developer machine cannot stand in for.

The nanosecond lookup metrics print but are absent from the baseline: on a shared virtual host they swing 33–35% run to run. The comparator reports unbaselined metrics without gating, and fails when a baseline metric is missing from the run.

## iris vs Capstone

A separate package one level down — methodology and recorded run in [`CapstoneComparison/README.md`](CapstoneComparison/README.md):

```sh
cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone
```

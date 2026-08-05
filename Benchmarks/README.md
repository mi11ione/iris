# iris benchmarks

The harness behind the README's performance table. Its own SwiftPM package, outside the root package graph, so the published `iris` package keeps zero dependencies. Build and run from this directory.

## Methodology

- **Machine class for the recorded numbers:** Apple M4 (4P+6E), 24 GiB, macOS 27, Swift 6.2.4, release build. Absolutes are host-relative; the ratios and stability claims are the portable part.
- **Buffer recipe**, deterministic from the seed: 3:1 pattern:random — three consecutive words from a cycling 12-word real-function template (each verified against llvm-mc 22.1.4), then one SplitMix64 word. The blend decodes ≈85% defined; the random quarter exercises undefined and exotic paths. Features `.arm64e`, default seed `0xc0ffee0015bad`.
- **Timing:** 1 unrecorded warmup + N recorded runs (`ContinuousClock`). Reported figure is the median, spread = (max − min) / median. Results fold into an opaque sink so the optimizer cannot delete the work.
- **Main-table configuration:** 256 MiB buffer, 9 runs, 10^7 lookups. The memory high-water figure is a single-run peak-RSS delta — a ceiling, not a byte-exact size.
- **What each metric's spread is worth.** Not every row resolves equally. `bulk-parallel` runs 4P+6E and reads 240–360M words/s across runs of the same binary — quote it as an order of magnitude, not a figure. `bulk-single`, `tier0-latency`, `session-lookup`, `real-listing` and the Capstone rows hold within ~5% and are quotable. The structural rows (`real-operands-per-word`, `real-retained-bytes-per-word`, `real-listing-bytes-per-word`) are counts, identical every run, and are the only rows a busy machine cannot move at all.
- **Comparing two builds:** two separately built binaries carry different code layout, and that bias does not average out with more passes. Anything under about 5% needs the two arms inside one process, not two runs of two binaries.

Throughput is sensitive to buffer size well beyond cache effects: the parallel modes allocate per-chunk record and operand storage concurrently, so a 256 MiB run and a 128 MiB run are not comparable. Quote the buffer size with any number.

## Reproduce

```sh
cd Benchmarks
swift run -c release iris-bench                 # the full battery (README numbers)
swift run -c release iris-bench bulk --mib 64   # one mode, custom buffer
swift run -c release iris-bench --json          # machine-readable results
```

Modes: `all` (default) · `memory` · `bulk` · `parallel` · `tier0` · `lookup` · `session` · `walk` · `text` · `real` · `compare` · `view-experiment` · `smoke`. Options: `--runs N` · `--mib N` · `--seed VALUE` · `--jobs N` · `--lookups N` · `--baseline FILE` · `--binary PATH` · `--deadline SECONDS` · `--json`.

Always run release; debug numbers are meaningless and the tool warns. `view-experiment` is the borrowing-view prototype that motivated the session tier (`Sources/iris-bench/ViewExperiment.swift`).

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

`real-retained-bytes-per-word` is the 64-byte record stride plus the operand buffer's 9/4-per-word reserve, and `real-operands-per-word` is what that reserve is sized against. Measuring either on the synthetic buffer reports the reserve as waste, because that buffer's operand density is nowhere near real code's.

## The regression smoke

Nightly CI runs `iris-bench smoke --json --baseline baseline.json` — a short configuration (64 MiB, 3 runs, 10^6 lookups) producing the full metric set.

`baseline.json` holds numbers recorded on the GitHub-hosted runner the workflow uses and gates exactly one metric: bulk-single throughput, stable there at about 4% intra-run spread. The floor is stale and sits far below current throughput, so it only catches a catastrophic regression; re-record it from a Nightly run on that host class, which a developer machine cannot stand in for. It fails only when the median falls below baseline×(1−tolerance) with tolerance 35%, making it a catastrophe canary for a real (~2× or worse) decode regression rather than a precise perf gate.

The nanosecond lookup metrics still run and print but are deliberately absent from `baseline.json`: on a shared virtual host they swing 33–35% run to run. The comparator reports any metric absent from the baseline without gating, and fails rather than skips when a baseline metric is missing from the run. Precise performance work runs the full suite above on a known quiet host.

## iris vs Capstone

A separate package one level down. Methodology, honesty notes, and the recorded run live in [`CapstoneComparison/README.md`](CapstoneComparison/README.md):

```sh
cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone
```

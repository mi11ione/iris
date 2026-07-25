# iris benchmarks

The harness behind the README's performance table. Its own SwiftPM package, outside the root package graph, so the published `iris` package keeps zero dependencies. Build and run from this directory.

## Methodology

- **Machine class for the recorded numbers:** Apple M4 (4P+6E), 24 GiB, macOS 27, Swift 6.2.4, release build. Absolutes are host-relative; the ratios and stability claims are the portable part.
- **Buffer recipe**, deterministic from the seed: 3:1 pattern:random — three consecutive words from a cycling 12-word real-function template (each verified against llvm-mc 22.1.4), then one SplitMix64 word. The blend decodes ≈85% defined; the random quarter exercises undefined and exotic paths. Features `.arm64e`, default seed `0xc0ffee0015bad`.
- **Timing:** 1 unrecorded warmup + N recorded runs (`ContinuousClock`). Reported figure is the median, spread = (max − min) / median. Results fold into an opaque sink so the optimizer cannot delete the work.
- **Main-table configuration:** 256 MiB buffer, 5 runs, 10^7 lookups. The memory high-water figure is a single-run peak-RSS delta — a ceiling, not a byte-exact size.

Throughput is sensitive to buffer size well beyond cache effects: the parallel modes allocate per-chunk record and operand storage concurrently, so a 256 MiB run and a 128 MiB run are not comparable. Quote the buffer size with any number.

## Reproduce

```sh
cd Benchmarks
swift run -c release iris-bench                 # the full battery (README numbers)
swift run -c release iris-bench bulk --mib 64   # one mode, custom buffer
swift run -c release iris-bench --json          # machine-readable results
```

Modes: `all` (default) · `memory` · `bulk` · `parallel` · `tier0` · `lookup` · `session` · `walk` · `text` · `view-experiment` · `smoke`. Options: `--runs N` · `--mib N` · `--seed VALUE` · `--jobs N` · `--lookups N` · `--baseline FILE` · `--json`.

Always run release; debug numbers are meaningless and the tool warns. `view-experiment` is the borrowing-view prototype that motivated the session tier (`Sources/iris-bench/ViewExperiment.swift`).

## The regression smoke

Nightly CI runs `iris-bench smoke --json --baseline baseline.json` — a short configuration (64 MiB, 3 runs, 10^6 lookups) producing the full metric set.

`baseline.json` holds numbers recorded on the GitHub-hosted runner the workflow uses and gates exactly one metric: bulk-single throughput, stable there at about 4% intra-run spread. It fails only when the median falls below baseline×(1−tolerance) with tolerance 35%, making it a catastrophe canary for a real (~2× or worse) decode regression rather than a precise perf gate.

The nanosecond lookup metrics still run and print but are deliberately absent from `baseline.json`: on a shared virtual host they swing 33–35% run to run. The comparator reports any metric absent from the baseline without gating, and fails rather than skips when a baseline metric is missing from the run. Precise performance work runs the full suite above on a known quiet host.

## iris vs Capstone

A separate package one level down. Methodology, honesty notes, and the recorded run live in [`CapstoneComparison/README.md`](CapstoneComparison/README.md):

```sh
cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone
```

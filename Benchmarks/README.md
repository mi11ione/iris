# Iris benchmarks

The harness behind the README's performance table. Its own SwiftPM
package (outside the root package graph, so the published `iris`
package keeps zero dependencies). Build and run from this directory.

## Methodology

- **Machine class for the recorded numbers:** Apple M4 (4P+6E),
  24 GiB, macOS 27, Swift 6.2.4, release build. Absolutes are
  host-class-relative. The ratios and stability claims are the
  portable part.
- **Buffer recipe (deterministic from the seed):** words generated 3:1
  pattern:random. Three consecutive words from a cycling 12-word
  real-function template (each verified against llvm-mc 22.1.4), then
  one SplitMix64 word. The blend decodes ≈84% defined, and the random
  quarter exercises undefined and exotic paths. Features `.arm64e`
  throughout. Default seed `0xc0ffee0015bad`.
- **Timing discipline:** every benchmark runs 1 unrecorded warmup +
  N recorded runs (`ContinuousClock`). The reported figure is the
  MEDIAN, spread = (max − min) / median. Observable results fold into
  an opaque sink so the optimizer cannot delete the work.
- **Main-table configuration:** 256 MiB buffer, 5 runs, 10^7 lookups
  (the full-battery defaults). The memory high-water figure is a
  single-run peak-RSS delta and is a ceiling, not a byte-exact size.

## Reproduce

```sh
cd Benchmarks
swift run -c release iris-bench                 # the full battery (README numbers)
swift run -c release iris-bench bulk --mib 64   # one mode, custom buffer
swift run -c release iris-bench --json          # machine-readable results
```

Modes: `all` (default) · `memory` · `bulk` · `parallel` · `tier0` ·
`lookup` · `session` · `walk` · `text` · `view-experiment` (the
borrowing-view prototype measurements that motivated the session
tier, see `Sources/iris-bench/ViewExperiment.swift`) · `smoke`. Options:
`--runs N` · `--mib N` · `--seed VALUE` · `--jobs N` · `--lookups N` ·
`--baseline FILE` · `--json`. Always run release. Debug numbers are
meaningless (the tool warns).

## The regression smoke

Nightly CI runs `iris-bench smoke --json --baseline baseline.json`:
a short configuration (64 MiB, 3 runs, 10^6 lookups) producing the
metrics pinned in `baseline.json`. Comparison is one-sided: throughput
gates only on falling below baseline×(1−tolerance), latency only on
exceeding baseline×(1+tolerance), with tolerance ±15%. A baseline
metric missing from the run fails rather than skips. The thresholds
are host-class-relative: on a different host class, re-record the
medians from that host's smoke output and keep the tolerance (the
note inside `baseline.json` says the same).

## Iris vs Capstone

The comparison harness is a separate package one level further down.
Methodology, honesty notes, and the recorded run live in
[`CapstoneComparison/README.md`](CapstoneComparison/README.md):

```sh
cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone
```

# Iris vs Capstone

Same-buffer decode-throughput comparison between Iris and
[Capstone](https://www.capstone-engine.org) v5, via the
[capstone-swift](https://github.com/zydeco/capstone-swift) bindings
(`next` branch, pinned by revision to the v5-compatible line, since
the repo has no v5 tag). This package exists two levels below the repository
root precisely so the third-party dependency can never enter the
published `iris` package graph.

## Reproduction

```sh
# libcapstone v5 via your package manager…
brew install capstone                  # macOS
apt install libcapstone-dev pkg-config # Ubuntu

# …or from source into a private prefix:
git clone --depth 1 --branch 5.0.6 https://github.com/capstone-engine/capstone
cd capstone && CAPSTONE_ARCHS=aarch64 CAPSTONE_BUILD_CORE_ONLY=yes make -j
PREFIX=$HOME/capstone-local make install
# (verify the installed capstone.pc paths match the prefix, and export)
export PKG_CONFIG_PATH=$HOME/capstone-local/lib/pkgconfig

cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone           # human-readable
swift run -c release iris-vs-capstone --json    # CI artifact
# options: --mib N (default 64) --runs N (default 3) --seed VALUE
```

The harness refuses to run against a non-5.x libcapstone (the detail
ABI changed across majors) and self-checks a 12-word llvm-mc-verified
prologue against expected mnemonics on BOTH engines before timing
anything. A version or ABI mismatch fails loudly and can never
silently skew the numbers.

## What is and is not compared

Identical input for every contender: the iris-bench deterministic
buffer (3:1 real-prologue pattern : SplitMix64 random words, ≈84%
defined, byte-identical recipe, same default seed). Single-threaded
on both sides (a Capstone handle is not thread-safe, and Iris's
parallel-by-chunks figure lives in `iris-bench`). 1 unrecorded warmup
+ N recorded runs, medians reported.

| benchmark | what runs | what it produces |
|---|---|---|
| `capstone-text` | `cs_disasm_iter`, detail OFF, SKIPDATA ON | text only |
| `capstone-detail` | `cs_disasm_iter`, detail ON, SKIPDATA ON | text + operands + reg reads/writes + groups |
| `iris-stream` | `InstructionStream` construction | operands + register sets + branch class + memory class + flag effects (always on, no reduced mode exists), text lazy and not rendered |
| `iris-stream-text` | construction + `.text` for every record | the above + text, output-parity with `capstone-text` |
| `capstone-bindings-probe` | capstone-swift `disassemble()`, 1 MiB slice | quantifies the Swift-binding overhead the C-direct loops deliberately bypass |

Honesty notes: Capstone's hot loops here call the C engine directly
(`cs_disasm_iter`, one reused insn buffer), so Capstone is measured at
its fastest rather than through binding allocations. SKIPDATA ON is
the closest analogue of Iris's UNDEFINED records (both sides
process every word of the buffer, and Capstone steps undecodable
AArch64 words as 4-byte `.byte` pseudo-instructions). Iris's canonical
text targets llvm-mc parity and is byte-different from Capstone's
operand spelling. Text CONTENT is not diffed here, only throughput.
Correctness lives in the `iris-parity` instruments against llvm-mc.

## Recorded run

Apple M4 (4P+6E), 24 GiB, macOS 27.0, Swift 6.2.4, libcapstone 5.0.6
(from-source, aarch64-only, static), 64 MiB buffer, seed
`0xc0ffee0015bad`, 3 runs, AC power on a quiet host (an earlier
battery-power run agreed within ~2% on every row):

| benchmark | median words/s | spread |
|---|---|---|
| `capstone-text` | 1,841,894 | 0.1% |
| `capstone-detail` | 1,799,876 | 0.3% |
| `iris-stream` | 19,023,254 | 0.8% |
| `iris-stream-text` | 6,132,729 | 0.6% |
| `capstone-bindings-probe` | 1,530,039 | 6.4% |

Iris decodes ~10.3× faster than Capstone-text and ~10.6× faster than
Capstone-detail while always computing more than detail mode produces.
At text output-parity Iris is ~3.3× faster.

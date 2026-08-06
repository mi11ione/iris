# iris vs Capstone

Same-buffer decode-throughput comparison against [Capstone](https://www.capstone-engine.org) v5, through the [capstone-swift](https://github.com/zydeco/capstone-swift) bindings (`next` branch, pinned by revision since the repo has no v5 tag). This package sits two levels below the repository root so the third-party dependency cannot enter the published `iris` package graph.

## Reproduction

```sh
# libcapstone v5 via your package manager…
brew install capstone                  # macOS
apt install libcapstone-dev pkg-config # Ubuntu

# …or from source into a private prefix:
git clone --depth 1 --branch 5.0.6 https://github.com/capstone-engine/capstone
cd capstone && CAPSTONE_ARCHS=aarch64 CAPSTONE_BUILD_CORE_ONLY=yes make -j
PREFIX=$HOME/capstone-local make install
export PKG_CONFIG_PATH=$HOME/capstone-local/lib/pkgconfig

cd Benchmarks/CapstoneComparison
swift run -c release iris-vs-capstone           # human-readable
swift run -c release iris-vs-capstone --json    # CI artifact
# options: --mib N (default 64) --runs N (default 3) --seed VALUE
```

The harness refuses a non-5.x libcapstone (the detail ABI changed across majors) and self-checks a 12-word llvm-mc-verified prologue against expected mnemonics on both engines before timing anything.

## What is compared

Identical input for every contender: the iris-bench deterministic buffer (3:1 real-prologue pattern : SplitMix64 random words, ≈85% defined, same recipe and default seed). Single-threaded on both sides, since a Capstone handle is not thread-safe. 1 unrecorded warmup + N recorded runs, medians reported.

| benchmark | what runs | what it produces |
|---|---|---|
| `capstone-text` | `cs_disasm_iter`, detail OFF, SKIPDATA ON | text only |
| `capstone-detail` | `cs_disasm_iter`, detail ON, SKIPDATA ON | text + operands + reg reads/writes + groups |
| `iris-stream` | `InstructionStream` construction | operands + register sets + branch class + memory class + flag effects (always on), text lazy |
| `iris-stream-text` | construction + `.text` for every record | the above + text, output-parity with `capstone-text` |
| `capstone-bindings-probe` | capstone-swift `disassemble()`, 1 MiB slice | the Swift-binding overhead the C-direct loops bypass |

Capstone's hot loops call the C engine directly (`cs_disasm_iter`, one reused insn buffer), so it is measured at its fastest. SKIPDATA ON is the closest analogue of iris's UNDEFINED records: both sides process every word. iris's text targets llvm-mc parity and is byte-different from Capstone's operand spelling, so text content is not diffed here, only throughput. Correctness lives in `iris-parity`.

## Recorded run

Apple M4 (4P+6E), 24 GiB, macOS 27.0, libcapstone 5.0.6, 64 MiB buffer, seed `0xc0ffee0015bad`, 5 runs. Medians of three consecutive batteries, which agreed within 0.6% on every row.

| benchmark | median words/s | spread |
|---|---|---|
| `capstone-text` | 1,768,923 | 0.8% |
| `capstone-detail` | 1,728,082 | 1.3% |
| `iris-stream` | 65,938,359 | 13.1% |
| `iris-stream-text` | 16,706,205 | 3.1% |
| `capstone-bindings-probe` | 1,497,170 | 2.1% |

iris decodes ~37× faster than Capstone-text and ~38× faster than Capstone-detail, while always computing more than detail mode produces. At text output-parity it is ~9.4× faster.

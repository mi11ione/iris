# iris

An ARM64/ARM64E disassembler with a semantic layer validated against LLVM. A command-line tool first, a Swift library underneath.

`iris --semantics` on an arm64e binary:

```
_helper:
100000398: d503237f  pacibsp
10000039c: d10083ff  sub sp, sp, #32                             ; reads=sp writes=sp
1000003a0: a9017bfd  stp x29, x30, [sp, #16]                     ; reads=x29,x30,sp mem=store
...
1000003b0: 97ffffde  bl 0x100000328 ; _add42                     ; writes=x30 branch=call
...
1000003d4: d65f0fff  retab                                       ; reads=x30,sp branch=return
```

Symbols and function starts from the binary, branch targets resolved and symbolicated, data-in-code rendered as data instead of garbage instructions — and a semantic column nothing else prints: registers read and written, memory behavior, branch class, all computed during decode and validated against `llvm-mc`.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/mi11ione/iris/main/install.sh | sh   # macOS universal, Linux x86_64/aarch64
brew install mi11ione/tap/iris
```

## Use it

```sh
$ iris MyApp.app/Contents/MacOS/MyApp           # full listing: symbols, function starts,
                                                # symbolicated branches, data-in-code kinds
$ iris disasm --arch arm64e --semantics MyApp   # the listing above, semantics on every line
$ iris functions MyApp                          # one row per function: address, name,
                                                # instruction count, calls, PAC use
$ iris stats MyApp                              # the extension census (PAC, MTE, AMX, crypto)
$ iris 0xd503233f                               # 0: d503233f  paciasp
$ iris --bytes "1f 20 03 d5"                    # 0: d503201f  nop
```

There are four verbs. `disasm` is the default, so `iris <file>` is the full listing; `iris 0x<word>` and `iris --bytes` infer `decode`, answering "what is this instruction" from a hex dump in one command. `stats` and `functions` are the other two. Run `iris <verb> --help` for a verb's options.

## Triage a crash from raw bytes

A crash report gives you a faulting PC and the bytes around it, and the binary is not on your machine. Decode the window anywhere — a Linux backend included — and read what faulted off the semantics:

```
$ iris --bytes "e0 07 40 f9 08 08 40 f9 c0 03 5f d6" --semantics
0: f94007e0  ldr x0, [sp, #8]                            ; reads=sp writes=x0 mem=load
4: f9400808  ldr x8, [x0, #16]                           ; reads=x0 writes=x8 mem=load
8: d65f03c0  ret                                         ; reads=x30 branch=return
```

Fault at offset 4? The record says it outright: a load through `x0`, sixteen bytes in. The bad pointer is `x0`.

## Audit what ships in your build

```
$ iris stats hello-arm64e
total words        56
undefined          0
data-in-code       0

extension sites:
  pointer-auth     4
  memory-tagging   0
  amx              0
  crypto           0
...
```

Gate CI on the answer — say, fail the build if PAC adoption ever drops to zero:

```sh
iris stats --json MyApp | jq -e '.extensions.pointerAuthentication > 0'
```

## Script it from any language

`--json` emits NDJSON under a versioned schema: one self-contained object per instruction, byte-stable across runs, so it pipes, diffs, and caches.

```sh
$ iris --json hello-arm64e | jq -r 'select(.branchClass=="call") | .address'
0x1000003b0
0x1000003bc
0x1000003f8
```

Byte-stability makes patch review mechanical: run `iris --json` over two versions of a binary and `diff` the streams — the only lines that differ are the instructions that changed. Exit codes, stdout/stderr separation, `--color auto|always|never`, and `--quiet` are all scripting-clean.

## Feed an LLM

The win for a model pipeline is structure. iris chunks a binary into functions, names the call edges between them, and produces byte-identical output for identical input, so prompts cache and evals reproduce. Unknown encodings stay UNDEFINED with the raw word preserved — a model is never handed a confident wrong instruction.

`iris functions` emits one object per function, the unit a prompt usually wants. Boundaries come from `LC_FUNCTION_STARTS` and section membership, so a function holds exactly its own instructions and never the trailing `__stubs` padding that grouping by symbol would sweep in. Each instruction names its function in `symbol` and carries a `targetSymbol` when a branch resolves, imports through a `__stubs` entry included — so a call graph reads straight off the stream:

```sh
$ iris --json MyApp | jq -c 'select(.branchClass=="call") | {from: .symbol, to: .targetSymbol, at: .address}'
{"from":"_helper","to":"_add42","at":"0x1000003b0"}
{"from":"_helper","to":"_sum_to","at":"0x1000003bc"}
{"from":"_main","to":"_helper","at":"0x1000003f8"}
```

Add `--slim` for the payload you actually hand a model: about half the default object's weight is constants repeating on every line, and slim drops them while keeping every signal-bearing field. Address-forming instructions carry the data they point at, so a model sees the format string without inferring it:

```sh
$ iris functions --json --slim strings-arm64 | jq -c '.instructions[] | select(.referencedString) | {text, referencedString}'
{"text":"add x8, x8, #1268","referencedString":"world"}
{"text":"add x0, x0, #1256","referencedString":"hello, %s!\n"}
```

## Decode from Swift

The same facts as typed fields, no text parsing:

```swift
import Iris

let words: [UInt8] = [0xFD, 0x7B, 0xBF, 0xA9,   // stp x29, x30, [sp, #-16]!
                      0x03, 0x00, 0x00, 0x94,   // bl #12
                      0xC0, 0x03, 0x5F, 0xD6]   // ret
let stream = InstructionStream(bytes: words, at: 0x4000)

for inst in stream where inst.isCall {
    print(inst.text, "->", String(inst.branchTarget ?? 0, radix: 16))
}
// bl #12 -> 4010
```

Every `Instruction` carries bit-exact register read/write sets, memory access and ordering, per-flag effects, ADR/ADRP page math, and precisely-scoped predicates — with scalable code treated in its own vocabulary (predicate, FFR, and ZA state in `scalableReads`/`scalableWrites`, streaming behavior in `scalableEffect`). It is the precomputed layer CFG builders, emulators, and decompilers otherwise write first.

No dependencies and no imports, so it runs anywhere Swift compiles: macOS, Linux, Windows, Android, and on-device iOS. CI builds every one.

```swift
dependencies: [
    .package(url: "https://github.com/mi11ione/iris", from: "0.6.0")
]
```

The [DocC articles](https://swiftpackageindex.com/mi11ione/iris/documentation) cover the full surface, including the retain-free `withSession` tier for hot loops.

## ISA coverage

| surface | status |
|---|---|
| Base ARM64 (DPI, branches/exception/system, loads & stores, DPR) | full, through the v9.6-era extensions llvm-mc recognizes (CSSC, FlagM, HBC, CHK, MOPS, LS64, RCPC tiers, D128, …) |
| NEON & floating point | full AdvSIMD + FP, including FP16, BF16, FP8, i8mm |
| SVE / SVE2 | full: integer, floating point, predicate/control, permute, and memory including gather/scatter and the fault variants |
| SME / SME2 | full: ZA tiles and array, outer products, multi-vector, ZT0 |
| Crypto | AES, SHA1/SHA256, SHA3/SHA512, SM3/SM4 |
| Pointer authentication | full: hint-space and authenticated branches on the base ISA, LDRAA/LDRAB behind `arm64e` |
| Memory tagging (MTE) | full tag-management set |
| Atomics | exclusives, LSE, LSE128, RCpc orderings |
| Apple AMX | decoded (Apple's undocumented coprocessor ISA, validated structurally since llvm-mc has no AMX target) |

All of it decodes with no flags to set, bar one: the ARM64E load tier (LDRAA/LDRAB), whose encodings mean something else on plain ARM64, follows the slice — automatic on an arm64e binary, `--features arm64e` on a raw word.

Every possible 32-bit word decodes to a well-formed record. Unknown encodings yield UNDEFINED with the raw word preserved: never a plausible-looking guess, never a crash.

## Why you can trust it

[![CI](https://github.com/mi11ione/iris/actions/workflows/ci.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/ci.yml)
[![Parity](https://github.com/mi11ione/iris/actions/workflows/parity.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/parity.yml)
[![Nightly](https://github.com/mi11ione/iris/actions/workflows/nightly.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/nightly.yml)
[![Platforms](https://github.com/mi11ione/iris/actions/workflows/platforms.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/platforms.yml)
[![Swift Package Index](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fmi11ione%2Firis%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/mi11ione/iris)

Correctness is defined by external oracles, never asserted from inside:

- The in-repo `iris-parity` tool diffs iris against `llvm-mc` at each encoding partition's maximal feature set — ≈600M rows harvested from real shipped Apple code, zero true divergences. It runs on every PR and on your machine.
- Nightly CI decodes the entire 2³² word space twice and asserts the digests match: every word decodes, deterministically, forever.
- Every known divergence from `llvm-mc` lives in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md) with evidence. There is exactly one — Apple AMX, which LLVM cannot decode at all — and anything uncatalogued fails the build.
- No decoder change merges without that battery green ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Performance

Apple M4, release build, 256 MiB mixed buffer, medians over 5 runs. Methodology and reproduction in [`Benchmarks/README.md`](Benchmarks/README.md).

- Bulk decode: 16.1M words/s single-thread, 117.7M words/s parallel.
- Address lookups: 11.0 ns stable (the pinned-session tier), 5.2 ns raw index arithmetic.
- Against Capstone v5 on identical input: **~10.3× faster** at decode while computing more than its detail mode, ~3.3× faster at text-output parity ([methodology](Benchmarks/CapstoneComparison/README.md)).

A nightly smoke guards these numbers with checked-in thresholds.

## Scope

iris is a disassembler. ARM64 only, decode only, one direction. It does not assemble, build CFGs, lift, recover types, or emulate, and it ships no Mach-O parsing as library API: the CLI's walker is internal, the library takes raw bytes, your loader owns file formats.

## License

Apache 2.0. See [LICENSE](LICENSE).

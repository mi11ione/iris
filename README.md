# iris

An ARM64/ARM64E disassembler with a semantic layer, validated against LLVM. A command-line tool first, a Swift library underneath.

```
$ iris --semantics MyApp
_helper:
100000398: d503237f  pacibsp
10000039c: d10083ff  sub sp, sp, #32                             ; reads=sp writes=sp
1000003a0: a9017bfd  stp x29, x30, [sp, #16]                     ; reads=x29,x30,sp mem=store
1000003b0: 97ffffde  bl 0x100000328 ; _add42                     ; writes=x30 branch=call
1000003d4: d65f0fff  retab                                       ; reads=x30,sp branch=return
```

Symbols and function starts come from the binary, branch targets resolve and symbolicate, data-in-code renders as data. The semantic column carries registers read and written, memory behavior and branch class, computed during decode and validated against `llvm-mc`.

## Install

macOS universal, Linux x86_64/aarch64:
```sh
curl -fsSL https://raw.githubusercontent.com/mi11ione/iris/main/install.sh | sh
```

Or Homebrew:
```sh
brew install mi11ione/tap/iris
```

## Use it

```sh
$ iris MyApp                                    # full listing
$ iris disasm --arch arm64e --semantics MyApp   # semantics on every line
$ iris functions MyApp                          # address, name, instruction count, calls, PAC
$ iris stats MyApp                              # extension census (PAC, MTE, AMX, crypto)
$ iris 0xd503233f                               # 0: d503233f  paciasp
$ iris --bytes "1f 20 03 d5"                    # 0: d503201f  nop
```

`disasm` is the default. `iris 0x<word>` and `--bytes` infer `decode`. `iris <verb> --help` lists a verb's options.

`--bytes` decodes at any address from any source, so a faulting window needs no file to point a tool at. These three words came out of a 515 MB kernel core and are `IOEventSource::closeGate()`:

```
$ iris --bytes "f3 03 00 aa 60 1a 40 f9 10 00 40 f9" --semantics
0: aa0003f3  mov x19, x0                                 ; reads=x0 writes=x19
4: f9401a60  ldr x0, [x19, #48]                          ; reads=x19 writes=x0 mem=load
8: f9400010  ldr x16, [x0]                               ; reads=x0 writes=x16 mem=load
```

`--at` gives that window its real base address, so a relative branch resolves where it points instead of against 0:

```
$ iris --bytes "0d fe ff 17" --at 0xfffffe0007b3c000
fffffe0007b3c000: 17fffe0d  b 0xfffffe0007b3b834
```

`+48` is `IOEventSource::workLoop`. The second load reads what the first produced, and the panic reported `far=0x0` — so `workLoop` was NULL. `reads=x0` names the faulting register without anyone parsing the addressing mode. [Full analysis](docs/kernel-panic-ncm.md).

## Machine-readable output

`--json` emits NDJSON under a versioned schema, byte-stable across runs, so it pipes, diffs and caches. Diffing two versions of a binary surfaces exactly the instructions that changed.

```sh
$ iris --json MyApp | jq -c 'select(.branchClass=="call") | {from: .symbol, to: .targetSymbol}'
{"from":"_helper","to":"_add42"}
{"from":"_helper","to":"_sum_to"}
{"from":"_main","to":"_helper"}

$ iris stats --json MyApp | jq -e '.extensions.pointerAuthentication > 0'   # gate CI on PAC adoption
```

`iris functions` emits one object per function, bounded by `LC_FUNCTION_STARTS` and section membership, so a function never sweeps in the trailing `__stubs` padding that grouping by symbol does. `--slim` drops the constants repeating on every line, roughly half the default weight, and address-forming instructions carry the data they point at:

```sh
$ iris functions --json --slim strings-arm64 | jq -c '.instructions[] | select(.referencedString) | {text, referencedString}'
{"text":"add x8, x8, #1268","referencedString":"world"}
{"text":"add x0, x0, #1256","referencedString":"hello, %s!\n"}
```

## From Swift

```swift
import Iris

let stream = InstructionStream(bytes: words, at: 0x4000)
for inst in stream where inst.isCall {
    print(inst.text, "->", String(inst.branchTarget ?? 0, radix: 16))
}
// bl #12 -> 4010

print(DisassemblyListing.render(stream))   // one line of canonical text per record
```

Every `Instruction` carries bit-exact register read/write sets, memory access and ordering, per-flag effects, ADR/ADRP page math, and precisely-scoped predicates. Scalable code gets its own vocabulary: predicate, FFR and ZA state in `scalableReads`/`scalableWrites`, streaming behavior in `scalableEffect`.

No dependencies and no imports, so it builds anywhere Swift does: macOS, Linux, Windows, Android, on-device iOS. CI builds every one.

```swift
dependencies: [
    .package(url: "https://github.com/mi11ione/iris", from: "1.0.0")
]
```

The [DocC articles](https://swiftpackageindex.com/mi11ione/iris/documentation) cover the full surface, including the retain-free `withSession` tier for hot loops.

## ISA coverage

| surface | status |
|---|---|
| Base ARM64 (DPI, branches/exception/system, loads & stores, DPR) | full, through the v9.6-era extensions llvm-mc recognizes (CSSC, FlagM, HBC, CHK, MOPS incl. the SETGO option forms, LS64, RCPC tiers, D128, …), with the system-register, `SYS`/`SYSL` alias, hint and barrier vocabularies llvm-mc knows at its maximum (BRB, MEC, RME, PMSA/MPU, GICv5, `PLBI`, `MLBI`) |
| NEON & floating point | full AdvSIMD + FP, including FP16, BF16, FP8, i8mm, FHM (`FMLAL`/`FMLSL`), FPRCVT, and the FP16/FP8 matrix-multiply and dot-product forms (`FMMLA`, `FDOT`) |
| SVE / SVE2 | full: integer, floating point, predicate/control, permute, memory including gather/scatter and the fault variants |
| SME / SME2 | full: ZA tiles and array, outer products, multi-vector, ZT0 |
| Crypto | AES, SHA1/SHA256, SHA3/SHA512, SM3/SM4 |
| Pointer authentication | full: hint-space and authenticated branches on the base ISA, PAuth_LR (`*SPPC`, `*SPPCR`, `*171615`), LDRAA/LDRAB behind `arm64e` |
| Memory tagging (MTE) | full tag-management set |
| Atomics | exclusives, LSE, LSE128, RCpc orderings, LSFE floating-point atomics, LSCP acquire/release pairs |
| Apple AMX | decoded (Apple's undocumented coprocessor ISA, validated structurally since llvm-mc has no AMX target) |
| Apple TIndex | `TCHANGEB`/`TCHANGEF`, `TENTER`, `TEXIT` |

One flag exists: the ARM64E load tier, whose encodings mean something else on plain ARM64. It follows the slice automatically, or `--features arm64e` on a raw word.

Every possible 32-bit word decodes to a well-formed record. Unknown encodings yield UNDEFINED with the raw word preserved: never a plausible-looking guess, never a crash.

## Correctness

[![CI](https://github.com/mi11ione/iris/actions/workflows/ci.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/ci.yml)
[![Parity](https://github.com/mi11ione/iris/actions/workflows/parity.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/parity.yml)
[![Nightly](https://github.com/mi11ione/iris/actions/workflows/nightly.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/nightly.yml)
[![Platforms](https://github.com/mi11ione/iris/actions/workflows/platforms.yml/badge.svg)](https://github.com/mi11ione/iris/actions/workflows/platforms.yml)
[![Swift Package Index](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fmi11ione%2Firis%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/mi11ione/iris)

Every claim is defined by an external oracle. The in-repo `iris-parity` tool diffs iris against `llvm-mc` at its maximal feature set (`-mattr=+all,+v9.6a`, the same for every encoding partition, so no partition's oracle can be blind to instructions the partition contains) — ≈600M rows from real shipped Apple code, zero true divergences — on every PR and on your machine. Nightly CI decodes the entire 2³² word space twice and asserts the digests match. Known divergences live in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md) with evidence; there is one, Apple AMX, which LLVM cannot decode at all, and anything uncatalogued fails the build. No decoder change merges without that battery green ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Performance

Apple M4, release build, medians over 9 runs. Methodology in [`Benchmarks/README.md`](Benchmarks/README.md).

Bulk decode runs 54.5M words/s single-thread and 302M parallel on a 256 MiB mixed buffer, 58.7M over real `__TEXT,__text`. Address lookup is 12.3 ns through the pinned-session tier, 5.1 ns raw; a single word through `decode(_:)` is 36.6 ns. A whole-stream listing renders at 30.9M instructions/s and the semantic column reads at 180M/s. Against Capstone v5 on identical input, **~37× faster** at decode while computing more than its detail mode, ~9.4× at text parity ([methodology](Benchmarks/CapstoneComparison/README.md)).

Whole-file disassembly against every other ARM64 disassembler on the machine, same thin arm64e slices, line counts included so a tool printing less is visible:

| `/usr/lib/dyld`, 169,165 instructions | time | lines |
|---|---|---|
| **iris** | **303 ms** | 175,902 |
| otool | 296 ms | 172,514 |
| llvm-objdump | 377 ms | 175,839 |
| objdump (Apple) | 408 ms | 175,839 |
| rizin | past the 20 s deadline | — |

## License

Apache 2.0. See [LICENSE](LICENSE).

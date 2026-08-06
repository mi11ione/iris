# Contributing to iris

## Ground rules

**The library imports nothing.** `Sources/Iris` carries zero `import` statements, not even Foundation, enforced by `Scripts/check-no-imports.sh`. A change that needs an import in the library is a design problem.

**100% coverage, per file, every column.** `Iris`, `IrisValidation` and `IrisCLICore` are held at 100% region/function/line coverage (`Scripts/coverage-gate.sh`). Coverage prevents crashes and dead code; correctness is owned by the oracles. Unreachable code is deleted, with the deletion carrying its unreachability argument.

**No decode-behavior change without an oracle.** Cite external ground truth: llvm-mc at the maximal `-mattr` (`+all,+v9.6a` — every family shares it), the ARM ARM section, or the documented structural reference for Apple-private surfaces like AMX. From 1.0, a canonical-text change is a minor version recorded in the release notes.

**Totality and determinism.** Every 4-byte word decodes to a well-formed record: no crash, no trap, no guess for unallocated space. Decode is a pure function of (word, address, features, data-in-code spans).

## What every decoder change must pass

```sh
swift test                                          # golden suites (full)
Scripts/check-no-imports.sh                         # zero-imports gate
Scripts/coverage-gate.sh                            # per-file 100% gate
swift build -c release --product iris-parity
.build/release/iris-parity tsv --family all         # synthetic corpora diff
.build/release/iris-parity live --family all        # live llvm-mc sweep
.build/release/iris-parity semantic --family all    # semantic-checker sweep
```

`iris-parity` needs `llvm-mc` (`brew install llvm` on macOS, apt.llvm.org on Linux; `IRIS_LLVM_MC=/path/to/llvm-mc` overrides discovery). It exits non-zero on any divergence not catalogued in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md).

Nightly CI also runs `iris-parity exhaustive all`: all 2³² words, totality plus two-pass digest determinism. Run it before and after any dispatch-level change.

## What a new family decoder must bring

`Sources/Iris/Decode/Scalable` and the `sve`/`sme` entries in `ParityFamily.swift` show every item below in place.

1. **The decoder** — dispatch-routed by encoding partition, zero imports, matching the existing shape: `internal` struct, draft-based, aliases resolved at decode time.
2. **A `Features` story.** A flag only when the same encoding space means different things on different targets. The ARM64E load tier is the only surface that qualifies.
3. **Golden encoding tables** in `Tests/IrisTests/Decode/` — `(encoding, mnemonic, operands, text)`, exhaustive per encoding group and representative per variant, plus semantic pins.
4. **A synthetic encoding table** — a tracked `Tests/Fixtures/Decode/synthetic-<family>.tsv` (`encoding_hex<TAB>expected_text`, empty expected means must-decode-UNDEFINED) harvested from llvm-mc at the maximal `-mattr`, with that mattr in the header comment.
5. **A `ParityFamily` registration** in `Sources/iris-parity`: op0 partitions or generation tiers, decode features, and semantic-checker routing. Every family is held to the single `ParityFamily.maximalMattr`; a per-family mattr can only blind the oracle to instructions that family's own partitions contain, which is how whole missing instruction families once read as agreement.
6. **An `@_spi(Validation)` semantic checker** — the per-mnemonic expected-attribute table the `semantic` subcommand sweeps.
7. **Known-deviations entries** for any by-design gap against llvm-mc, each with reproducible evidence and the oracle version.
8. **Green everything**, including a `live` sweep of the new family at `--count 65536` or more.

## Code rules

- **Swift Testing.** `@Suite`/`@Test`/`#expect`, one `///` per suite saying what it validates and no doc comments elsewhere in a test file. Tests drive public API only: no `@testable import`, no test-only APIs.
- **No `try`/`throw` in the library.** Parsing returns optionals, decode returns UNDEFINED records. `fatalError` is banned in decode paths: hostile input produces diagnostics.
- **Fixed-width integers for binary data.** `UInt8`/`UInt16`/`UInt32`/`UInt64` for encodings, fields, offsets, sizes; `UInt64` for VM addresses. `Int` is for collection indices and counts.
- **Value types with structural `Sendable`.** `@frozen` public structs and enums with stable layout. No `@unchecked Sendable`, no locks.
- **Naming discipline.** Properties are nouns, methods are verbs, argument labels read as a phrase at the call site. No abbreviations beyond domain-standard (ARM64, PAC, MTE, …).
- **Performance annotations with a reason.** `@inlinable`/`@inline(__always)` on hot helpers, capacity reservation in buffer code, thresholds documented with their measured rationale. No `print` in production code.
- **No availability-gated stdlib.** An `@available` floor raises the package's deployment minimum and drops platforms with it. `Float16` is macOS 11 / iOS 14 and up and would exclude Intel macOS, so half-precision is done by bit manipulation (`SIMDFPCanonicalizer.halfBitsToDouble(_:)`, `SVEFPBinaryDecode.halfBits(of:)`). The Release workflow's universal-binary job catches a slip; a local build may not.
- **Keep bit-twiddling expressions explicitly typed.** Pin the intermediate (`let bits: UInt32 = …`) and narrow once. Untyped, a multi-term shift/mask chain becomes one constraint system over every integer type, which older toolchains give up on.

Read two existing files of the kind you are changing first.

## Bugs found during trust work

If a sweep surfaces a decode bug while decode behavior must stay frozen, record it as an `open-defect` entry in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md) so the harness stays green while the defect stays visible. Fix it in a follow-up that removes the entry.

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Crash-on-hostile-input qualifies as a vulnerability here — see [SECURITY.md](SECURITY.md).

# Contributing to iris

iris's correctness claims are externally earned and continuously re-verified. This document is the bar every change is held to. It is deliberately strict — that trust infrastructure is what makes contributions safe to accept at all, including whole new family decoders.

## Ground rules

**The library imports nothing.** `Sources/Iris` carries zero `import` statements, not even Foundation, enforced by `Scripts/check-no-imports.sh`. A change that needs an import in the library is a design problem.

**100% coverage, per file, every column.** `Iris`, `IrisValidation`, and `IrisCLICore` are held at 100% region/function/line coverage (`Scripts/coverage-gate.sh`). Coverage prevents crashes and dead code; correctness is owned by the oracles below. Unreachable code is deleted rather than decorated with tests, and the deletion carries its unreachability argument.

**No decode-behavior change without an oracle.** Any change to what a word decodes to must cite external ground truth: llvm-mc at the family's maximal `-mattr`, the ARM ARM section, or the documented structural reference for Apple-private surfaces like AMX. "It looks right" does not merge. From 1.0, any canonical-text change is a minor version recorded in the release notes.

**Totality and determinism are non-negotiable.** Every 4-byte word decodes to a well-formed record — no crash, no trap, no plausible-looking guess for unallocated space. UNDEFINED is the honest answer. Decode is a pure function of (word, address, features, data-in-code spans).

## What every decoder change must pass

Run these before opening a PR; CI runs them again.

```sh
swift test                                          # golden suites (full)
Scripts/check-no-imports.sh                         # zero-imports gate
Scripts/coverage-gate.sh                            # per-file 100% gate
swift build -c release --product iris-parity
.build/release/iris-parity tsv --family all         # synthetic corpora diff
.build/release/iris-parity live --family all        # live llvm-mc sweep
.build/release/iris-parity semantic --family all    # semantic-checker sweep
```

`iris-parity` needs `llvm-mc` (`brew install llvm` on macOS, apt.llvm.org on Linux; `IRIS_LLVM_MC=/path/to/llvm-mc` overrides discovery). It exits non-zero on any divergence not catalogued in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md). A new unexplained divergence is a finding to fix, or to catalogue with evidence — never to ignore.

Nightly CI additionally runs `iris-parity exhaustive all`: all 2³² words, totality plus two-pass digest determinism. Run it yourself before and after any dispatch-level change.

## What a new family decoder must bring

The scalable families are the worked example — read `Sources/Iris/Decode/Scalable` and the `sve`/`sme` entries in `ParityFamily.swift` to see every item below in place. A family decoder PR is welcome and must arrive whole:

1. **The decoder** — dispatch-routed by encoding partition, zero imports, matching the existing shape (`internal` struct, draft-based, aliases resolved at decode time). Read two existing decoders first.
2. **A `Features` story.** A flag only when the same encoding space means different things on different targets; otherwise the extension decodes unconditionally. The ARM64E load tier is the only surface that qualifies.
3. **Golden encoding tables** in `Tests/IrisTests/Decode/` — `(encoding, mnemonic, operands, text)`, exhaustive per encoding group and representative per variant, plus semantic pins for reads/writes, branch class, memory behavior, flag effects.
4. **A synthetic encoding table** — a tracked `Tests/Fixtures/Decode/synthetic-<family>.tsv` (`encoding_hex<TAB>expected_text`, empty expected means must-decode-UNDEFINED) harvested from llvm-mc at the family's maximal `-mattr`, with that mattr in the header comment.
5. **A `ParityFamily` registration** in `Sources/iris-parity`: op0 partitions or generation tiers, the family's maximal `-mattr` with a note on why each feature is present, decode features, and semantic-checker routing.
6. **An `@_spi(Validation)` semantic checker** — the per-mnemonic expected-attribute table the `semantic` subcommand sweeps.
7. **Known-deviations entries** for any by-design gap against llvm-mc, each with reproducible evidence and the oracle version.
8. **Green everything**, including a `live` sweep of the new family at meaningful volume (`--count 65536` or more).

That list is exactly what the existing nine families carry. None of it is optional ceremony.

## Code rules

- **Swift Testing.** `@Suite`/`@Test`/`#expect`, every suite carrying a `///` comment saying what it validates. Tests drive public API only — no `@testable import`, no test-only APIs.
- **No `try`/`throw` in the library.** Parsing returns optionals, decode returns UNDEFINED records. `fatalError` is banned in decode paths: hostile input must produce diagnostics, never a crash.
- **Fixed-width integers for binary data.** `UInt8`/`UInt16`/`UInt32`/`UInt64` for encodings, fields, offsets, sizes; `UInt64` for VM addresses. `Int` is for collection indices and counts.
- **Value types with structural `Sendable`.** `@frozen` public structs and enums with stable layout. No `@unchecked Sendable`, no locks.
- **Naming discipline.** Properties are nouns, methods are verbs, argument labels read as a phrase at the call site. No abbreviations beyond domain-standard (ARM64, PAC, MTE, …).
- **Deliberate performance annotations.** `@inlinable`/`@inline(__always)` on hot helpers, capacity reservation in buffer code, threshold choices documented with their measured rationale. No `print` in production code — diagnostics are typed values.
- **No availability-gated stdlib.** Anything carrying an `@available` floor raises the package's deployment minimum and drops platforms with it. `Float16` is the one that keeps tempting: it is macOS 11 / iOS 14 and up, and referencing it excludes Intel macOS, so half-precision is done by bit manipulation instead (`SIMDFPCanonicalizer.halfBitsToDouble(_:)` decoding, `SVEFPBinaryDecode.halfBits(of:)` encoding). The Release workflow's universal-binary job is what catches a slip — a local build need not, since the deployment target it infers depends on the toolchain.
- **Keep bit-twiddling expressions explicitly typed.** Pin the intermediate (`let bits: UInt32 = …`) and narrow once, rather than wrapping a multi-term shift/mask chain in a bare `UInt8(…)`. Untyped, the whole chain becomes one constraint system over every integer type, which older toolchains than your local one give up on with "unable to type-check this expression in reasonable time".

Read two existing files of the kind you are changing first. The codebase is the style guide.

## Bugs found during trust work

If a sweep surfaces a decode bug while decode behavior must stay frozen, record it as an `open-defect` entry in [`KNOWN-DEVIATIONS.md`](KNOWN-DEVIATIONS.md) so the harness stays green while the defect stays visible. Fix it in a dedicated follow-up that removes the entry.

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Crash-on-hostile-input qualifies as a vulnerability here — see [SECURITY.md](SECURITY.md) for what qualifies and how to report privately.

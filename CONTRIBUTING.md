# Contributing to Iris

Iris's correctness claims are externally earned, continuously re-verified, and
never weakened for convenience. This document encodes the bar every change is
held to. It is deliberately strict. The trust infrastructure is what makes
contributions safe to accept at all, including whole new family decoders.

## The ground rules

**The library imports nothing.** `Sources/Iris` carries zero `import`
statements, not even Foundation. `Scripts/check-no-imports.sh` enforces this
mechanically in CI. A change that needs an import in the library is a design
problem.

**100% coverage, per file, every column.** The library target is held at
100% region/function/line coverage (`Scripts/coverage-gate.sh`). Coverage
prevents crashes and dead code. Correctness is owned by the oracles below.
Unreachable code is deleted rather than decorated with tests, and a deletion
carries its unreachability argument in the change that removes it.

**No decode-behavior change without an oracle.** Any change to what a word
decodes to (mnemonic, operands, semantics, text) must cite external ground
truth: llvm-mc output at the family's maximal `-mattr`, the ARM Architecture
Reference Manual section, or (for Apple-private surfaces like AMX) the
documented structural reference. "It looks right" does not merge. Canonical
text is additionally under the text-stability policy: from 1.0, any rendering
change is a minor version, recorded in the release notes.

**Totality and determinism are non-negotiable.** Every possible 4-byte word
must decode to a well-formed record: no crash, no trap, no plausible-looking
guess for unallocated space. UNDEFINED is the honest answer. Decode must be
a pure function of (word, address, features, data-in-code spans).

## What every decoder change must pass

Run these locally before opening a PR. CI runs them all again.

```sh
swift test                                          # golden suites (full)
Scripts/check-no-imports.sh                         # zero-imports gate
Scripts/coverage-gate.sh                            # per-file 100% gate
swift build -c release --product iris-parity
.build/release/iris-parity tsv --family all         # synthetic corpora diff
.build/release/iris-parity live --family all        # live llvm-mc sweep
.build/release/iris-parity semantic --family all    # semantic-checker sweep
```

`iris-parity` needs `llvm-mc` (Homebrew `brew install llvm` on macOS,
apt.llvm.org on Linux, and `IRIS_LLVM_MC=/path/to/llvm-mc` overrides
discovery). The tool exits non-zero on any divergence not catalogued in
`KNOWN-DEVIATIONS.md`. That catalogue is the complete list of expected
Iris↔llvm-mc gaps, and each entry carries evidence and the oracle version.
A new unexplained divergence is a finding to fix or (with evidence) to
catalogue, never to ignore. Nightly CI additionally runs the exhaustive sweep
(`iris-parity exhaustive all`): all 2³² words, totality plus two-pass digest
determinism. Run it yourself before and after any dispatch-level change.

## What a new family decoder must bring

The flagship example is SME/SVE/SVE2 (the op0 0-3 space, UNDEFINED today,
post-1.0 roadmap). A PR adding a family decoder is welcome and must
arrive whole:

1. **The decoder**, dispatch-routed by encoding partition, zero imports,
   matching the existing family-decoder shape (`internal` struct, draft-based,
   alias rules resolved at decode time). Read two existing decoders first.
2. **A `Features` story.** New architecture extensions arrive behind
   `Features` flags so existing callers see no behavior change. The feature
   default for v1 surfaces is documented on the flag.
3. **Golden encoding tables.** Per-instruction-class test suites in
   `Tests/IrisTests/Decode/` (the table style: `(encoding, expected mnemonic,
   expected operands, expected text)`, exhaustive per encoding group,
   representative per variant), plus semantic-attribute pins for reads/writes,
   branch class, memory behavior, flag effects.
4. **A synthetic encoding table.** A tracked `Tests/Fixtures/Decode/synthetic-<family>.tsv`
   (`encoding_hex<TAB>expected_text`, empty expected = must decode UNDEFINED)
   harvested from llvm-mc at the family's maximal `-mattr`, with the harvest
   mattr recorded in the header comment.
5. **A `ParityFamily` registration** in `Sources/iris-parity`: op0
   partitions or generation tiers, the family's MAXIMAL `-mattr` (the oracle
   contract, with a note on why each feature is present), decode features, and
   the semantic-checker routing.
6. **An `@_spi(Validation)` semantic checker**, the per-mnemonic
   expected-attribute table the `semantic` subcommand sweeps.
7. **Known-deviations entries** for any by-design gap against llvm-mc the
   family introduces, each with reproducible evidence (`encoding → iris text
   vs oracle text`, oracle version).
8. **Green everything**: the full local battery above, including a `live`
   sweep of the new family at meaningful volume (`--count 65536` or more).

That list is exactly what the existing six families carry. Nothing in it is
optional ceremony.

## Code rules

The mechanical bar PRs are audited against, rule by rule:

- **Swift Testing.** `@Suite`/`@Test`/`#expect`, every suite carrying a `///`
  comment saying what it validates. Tests drive public API only (no
  `@testable import`, no test-only APIs).
- **No `try`/`throw` in the library.** Parsing returns optionals and decode
  returns UNDEFINED records. `fatalError` is banned in decode paths, because
  hostile input must produce diagnostics and never a crash.
- **Fixed-width integers for binary data.** `UInt8`/`UInt16`/`UInt32`/
  `UInt64` for encodings, fields, offsets, and sizes, with `UInt64` for VM
  addresses. `Int` is for collection indices and counts.
- **Value types with structural `Sendable`.** `@frozen` public structs and
  enums with stable layout, no `@unchecked Sendable`, no locks.
- **Naming discipline.** Properties are nouns, methods are verbs, and
  argument labels read as a phrase at the call site. No abbreviations beyond
  domain-standard (ARM64, PAC, MTE, …).
- **Performance annotations are deliberate.** `@inlinable`/`@inline(__always)`
  on hot helpers, capacity reservation in buffer code, and threshold-based
  algorithm choices documented with their measured rationale. No `print` in
  production code, diagnostics are typed values.

Read two existing files of the kind you are changing first. The codebase is
the style guide.

## Library bugs found during trust work

If a parity or semantic sweep surfaces a decode bug at a moment when decode
behavior must stay frozen (for example mid-way through tooling work), record
it as an `open-defect` entry in `KNOWN-DEVIATIONS.md` so the harness stays
green while the defect stays visible. Fix it in a dedicated follow-up change
that removes the entry.

## Conduct and security

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Crash-on-hostile-input qualifies as a vulnerability here. See
[SECURITY.md](SECURITY.md) for what qualifies and how to report privately.

# Scope & guarantees

What iris promises, what it deliberately does not do, and where every known gap is written down.

## The guarantees

**Totality.** Every possible 4-byte word decodes into a well-formed record. Unknown or unallocated encodings produce UNDEFINED with the raw bytes preserved — never a plausible-looking wrong answer, never a crash, never undefined behavior. A buffer whose length is not a multiple of 4 gets an explicit truncated-tail record for the residual bytes.

**Determinism and purity.** Decode is a pure function of (bytes, base address, features, data-in-code spans). The same input produces the same records and the same text on every platform and every run. The nightly suite decodes the entire 2³² word space twice and asserts digest equality.

**Semantic correctness at the architectural level.** Register read/write sets are bit-exact and independent of alias presentation; branch, memory, ordering, and flag classifications match the ARM specification. These claims are validated externally, by a parity harness that lives in the repository and runs in CI against `llvm-mc` — committed synthetic corpora, seeded live sweeps, and hundreds of millions of rows harvested from real shipped Apple code. Correctness is defined outside the library.

**Typed diagnostics.** Conditions worth surfacing (data-in-code spans encountered, address-space wrap) are typed ``Diagnostic`` values on the stream. Nothing is silently dropped, nothing silently guessed.

## The walls

iris is a disassembler, and the boundary is policed deliberately. It does not assemble — decode is one direction only. It does not build control-flow graphs, lift to an IR, recover types, or emulate. It decodes ARM64 (AArch64) only: no x86, no 32-bit ARM. And it ships no Mach-O or ELF parsing as library API — the command-line tool's Mach-O walker is internal to the tool, and the library's bulk tier takes raw bytes by design (see <doc:DisassemblingWithYourOwnLoader>).

## What needs a feature flag

Almost nothing. NEON and floating point, crypto, MTE, the atomics tiers, Apple's AMX coprocessor, and the scalable tiers (SVE/SVE2 and SME/SME2) all decode unconditionally.

```swift
print(decode(0x04220020).text)                     // "add z0.b, z1.b, z2.b"
print(decode(0xC0080000).text)                     // "zero {}"
```

``Features`` exists for the one case that genuinely needs a target decision: an encoding space meaning different things on different targets. That is the ARM64E load tier alone (``Features/pointerAuthentication``, spelled ``Features/arm64e``), where LDRAA/LDRAB occupy words unallocated on plain ARM64. The command-line tool reads it from the Mach-O slice, so only a raw word needs `--features arm64e`.

## What UNDEFINED does and does not claim

The UNDEFINED record is a provenance statement about *iris*, not about the bytes. Two situations produce it: genuinely unallocated encodings, and ARM64E load-tier words decoded without ``Features/arm64e``.

Conversely, iris cannot know what *you* fed it. Encrypted regions (FairPlay-protected code is the classic case), compressed data, or plain garbage decode to whatever those bytes happen to be — sometimes UNDEFINED, sometimes well-formed nonsense. The guarantee is that records honestly describe the bytes given. Knowing a range is ciphertext rather than code is loader-level knowledge you own, exactly like data-in-code spans (<doc:DataInCode>).

## Known deviations from the oracle

iris's text targets `llvm-mc`'s conventions, and every known divergence is catalogued with evidence and the oracle version in `KNOWN-DEVIATIONS.md`. That catalogue is machine-readable and wired into the parity harness: divergences it explains are reported under their entry id, anything unexplained fails the run.

It holds exactly one entry: Apple's undocumented AMX coprocessor instructions, which iris decodes — validated structurally against the community reference — and `llvm-mc` rejects, having no AMX target.

## Where the bar is enforced

Four layers keep these claims true on every change: per-family golden encoding suites, the in-repo `iris-parity` harness diffing iris against `llvm-mc` at maximal feature sets, nightly exhaustive 2³² totality and determinism sweeps, and a contribution bar (`CONTRIBUTING.md`) under which no decoder change merges without the battery green. The library targets are additionally held at 100% test coverage, and `Iris` itself at zero `import` statements, both gated mechanically in CI.

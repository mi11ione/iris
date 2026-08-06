# Guarantees

**Totality.** Every possible 4-byte word decodes into a well-formed record. Unknown or unallocated encodings produce UNDEFINED with the raw bytes preserved: no plausible-looking wrong answer, no crash, no undefined behavior. A buffer whose length is not a multiple of 4 gets a truncated-tail record for the residual bytes.

**Determinism.** Decode is a pure function of (bytes, base address, features, data-in-code spans). The same input produces the same records and the same text on every platform and every run. The nightly suite decodes the entire 2³² word space twice and asserts digest equality.

**Semantic correctness.** Register read/write sets are bit-exact and independent of alias presentation; branch, memory, ordering and flag classifications match the ARM specification. A parity harness in the repository validates them in CI against `llvm-mc`: committed synthetic corpora, seeded live sweeps, and hundreds of millions of rows from real shipped Apple code.

**Typed diagnostics.** Data-in-code spans encountered and address-space wrap surface as ``Diagnostic`` values on the stream.

## Features

``Features`` covers the one case needing a target decision: an encoding space meaning different things on different targets. That is the ARM64E load tier (``Features/pointerAuthentication``, spelled ``Features/arm64e``), where LDRAA/LDRAB occupy words unallocated on plain ARM64. The command-line tool reads it from the Mach-O slice, so only a raw word needs `--features arm64e`.

## What UNDEFINED claims

UNDEFINED is a statement about iris, not about the bytes. Two situations produce it: unallocated encodings, and ARM64E load-tier words decoded without ``Features/arm64e``.

iris cannot know what you fed it. Encrypted regions, compressed data or plain garbage decode to whatever those bytes happen to be — sometimes UNDEFINED, sometimes well-formed nonsense. Records honestly describe the bytes given. Knowing a range is ciphertext is loader-level knowledge you own, like data-in-code spans (<doc:DataInCode>).

## Known deviations

iris's text targets `llvm-mc`'s conventions. Every known divergence is catalogued with evidence and the oracle version in `KNOWN-DEVIATIONS.md`, which the parity harness reads: divergences it explains are reported under their entry id, anything unexplained fails the run.

It holds one entry: Apple's undocumented AMX coprocessor instructions, which iris decodes — validated structurally against the community reference — and `llvm-mc` rejects, having no AMX target.

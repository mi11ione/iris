# Scope & guarantees

What Iris promises, what it deliberately does not do, and where every known
gap is written down.

## The guarantees

**Totality.** Every possible 4-byte word decodes safely into a well-formed
record. Unknown or unallocated encodings produce UNDEFINED records with the
raw bytes preserved. There is never a plausible-looking wrong answer, never
a crash, never undefined behavior. Buffers whose length is not a multiple
of 4 produce an explicit truncated-tail record for the residual bytes.

**Determinism and purity.** Decode of a buffer is a pure function of
(bytes, base address, features, data-in-code spans). The same input produces
the same records and the same text on every platform and every run. The
nightly trust suite decodes the entire 2^32 word space twice and asserts
digest equality.

**Semantic correctness at the architectural level.** Register read/write
sets are bit-exact and independent of alias presentation. Branch, memory,
ordering, and flag classifications match the ARM architecture specification.
These claims are validated externally by a parity harness that lives in the
repository and runs in CI, against `llvm-mc` over committed synthetic
corpora, seeded live sweeps, and tens of millions of rows harvested from
real, shipped Apple code. Correctness is defined outside the library.

**Typed diagnostics.** Conditions worth surfacing (data-in-code spans
encountered, address-space wrap) are typed ``Diagnostic`` values on the
stream. Nothing is silently dropped and nothing is silently guessed.

## The walls

Iris is a disassembler, and the boundary is policed deliberately. It does
not assemble (decode is one direction only). It does not build
control-flow graphs, lift to an IR, recover types, or emulate. It decodes
ARM64 (AArch64) only, no x86, no 32-bit ARM. And it ships no Mach-O or ELF
parsing as library API: the `iris` command-line tool's Mach-O walker is
internal to the tool, and the library's bulk tier takes raw bytes by design
(see <doc:DisassemblingWithYourOwnLoader>).

## SVE, SME, and SVE2 decode as UNDEFINED

The scalable-vector and scalable-matrix extension encodings (the op0 0–3
space) are not decoded at this version. Those words return UNDEFINED
records, exactly like unallocated encodings. This is a documented scope
decision with a real consequence worth stating prominently: **Apple silicon
now ships SME**, so streaming-mode matrix code in current binaries will
surface as UNDEFINED words rather than instructions. The gap is first on
the post-1.0 roadmap, and the trust infrastructure (golden suites, llvm-mc
parity, exhaustive sweeps) is exactly what makes a contributed SME/SVE
family decoder safe to accept.

If you census binaries today, ``Instruction/isUndefined`` over an SME-using
function tells you truthfully that Iris decodes nothing there. It does not
tell you the bytes are meaningless.

## What UNDEFINED does and does not claim

The UNDEFINED record is a provenance statement about *Iris* itself rather
than about the bytes. Three situations produce it: genuinely unallocated
encodings, encodings of extensions absent from the decode ``Features``, and
encodings of extensions Iris does not yet implement (SVE/SME). Conversely,
Iris cannot know what *you* fed it: encrypted regions (FairPlay-protected
code is the classic case), compressed data, or plain garbage decode to
whatever those bytes happen to be, sometimes UNDEFINED and sometimes
well-formed nonsense instructions. Iris guarantees the records honestly
describe the bytes it was given. Knowing that a range is ciphertext rather
than code is the caller's loader-level knowledge, exactly like data-in-code
spans (<doc:DataInCode>).

## Known deviations from the oracle

Iris's text targets `llvm-mc`'s conventions, and every known divergence is
catalogued with evidence and the oracle version in `KNOWN-DEVIATIONS.md` at
the repository root. The catalogue is machine-readable and wired into the
parity harness: divergences it explains are reported under their entry id,
and anything unexplained fails the run. At this release the catalogue holds
exactly one entry: Apple's undocumented AMX coprocessor instructions, which
Iris decodes (validated structurally against the community reference) and
`llvm-mc` rejects, because LLVM has no AMX target support.

## Where the bar is enforced

Four layers keep these claims true on every change: per-family golden
encoding suites, the in-repo `iris-parity` harness diffing Iris against
`llvm-mc` at maximal feature sets, nightly exhaustive 2^32 totality and
determinism sweeps, and a contribution bar (`CONTRIBUTING.md`) under which
no decoder change merges without the battery green. The library target is
additionally held at 100% test coverage and zero `import` statements,
both gated mechanically in CI.

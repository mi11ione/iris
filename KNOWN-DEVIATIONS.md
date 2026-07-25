# Known deviations

Every expected divergence between iris and the `llvm-mc` oracle, with evidence.

This file is documentation and a machine-readable table at once: `iris-parity` parses the entry table below, classifies matching divergences under their entry id, and reports them on every run without gating. Anything it reports that is **not** in this table gates the build. The parity contract is zero unexplained rows.

Two statuses exist:

- **`expected`** — a by-design gap between iris's scope and the oracle's, or the reverse. Permanent until the scope changes.
- **`open-defect`** — a recorded iris bug awaiting a dedicated fix, catalogued rather than hidden when decode behavior must stay frozen during tooling work. The entry **must** be removed by the change that fixes it.

## Matcher mini-language

All clauses must hold: `iris.category=<name>` · `iris.mnemonic=<name>` · `oracle=invalid` (empty oracle text) · `oracle.prefix=<token>` · `encoding.mask=0xMASK:0xVALUE` (`encoding & MASK == VALUE`) · `field=<name>`.

`field` names the semantic checker issue's field (e.g. `branchClass`), pinning an entry to one recorded checker defect instead of every future semantic issue on the same records. Text divergences carry no field, so the clause never matches them.

One routing clause sits alongside the constraints: `check=semantic` scopes an entry to the `semantic` subcommand's checker issues, and entries without it classify text-parity divergences (`tsv`/`live`) only. An entry never crosses instruments — a semantic deviation must not mask a text divergence, or the reverse.

## Entry table

| id | status | matcher | evidence |
|---|---|---|---|
| `amx-apple-coprocessor` | expected | `iris.category=amx; oracle=invalid` | iris decodes Apple's undocumented AMX coprocessor instructions (`0x00201000`-magic words in the op0 0-3 reserved tier); llvm-mc has no AMX target and rejects every one. Example: `0x00201000` → iris `ldx x0`, llvm-mc 22.1.4 `invalid instruction encoding`. The AMX decode is validated structurally against the corsix AMX reference, not against llvm-mc. |

## What is deliberately not here

**Harvest-era oracle-blind TSV cells.** Rows in `real_text.tsv` files whose expected column was captured at a narrower `-mattr` than the family maximum (each TSV's header comment records its harvest mattr). This is an artifact of the file, handled structurally: `iris-parity tsv --reanchor` re-drives every divergent row through llvm-mc at the family's maximal mattr and reports rows where iris matches the live oracle as `oracle-blind`, separately from true divergences. A static catalogue entry would risk masking real regressions on those words.

**SVE/SME/SVE2 encodings.** Not a deviation. The `sve` and `sme` families own those tiers, carry their own synthetic corpora, and sweep at the maximal scalable `-mattr` divergence-free. The `reserved` family covers op0 1 and 3, which are architecturally unallocated. Every family whose partitions reach a scalable tier — including the `reserved` slab that shares op0 0 with the SME region — runs its oracle at the scalable mattr, so oracle and iris never disagree about who decodes what.

**The `LSGoldenCorpusTests` / `DPRGoldenCorpusTests` skip lists** (structured SIMD LD1-LD4/ST1-ST4, MTE tags, MOPS, LS64, LSE128, RPRFM, the PAC DPR tier, RMIF/SETF). Every row they name decodes to the oracle text through the composed dispatcher, and all five in-repo synthetics diff clean with no skip filters. The lists survive in those suites as harmless over-protection; the parity tool applies none of them, and none of it is a deviation.

Oracle version for all evidence here: Homebrew LLVM 22.1.4 (`llvm-mc`), `-triple=arm64-apple-macos`.

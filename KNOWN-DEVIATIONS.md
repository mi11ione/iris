# Known deviations

Every expected divergence between iris and the `llvm-mc` oracle, with evidence.

This file is documentation and a machine-readable table at once: `iris-parity` parses the entry table, classifies matching divergences under their entry id, and reports them without gating. Anything it reports that is **not** in the table gates the build.

Two statuses exist. `expected` is a by-design gap between iris's scope and the oracle's, permanent until the scope changes. `open-defect` is a recorded iris bug awaiting a dedicated fix, catalogued so it stays visible while decode behavior is frozen during tooling work; the entry must be removed by the change that fixes it.

## Matcher mini-language

All clauses must hold: `iris.category=<name>` · `iris.mnemonic=<name>` · `oracle=invalid` (empty oracle text) · `oracle.prefix=<token>` · `encoding.mask=0xMASK:0xVALUE` (`encoding & MASK == VALUE`) · `field=<name>`.

`field` names the semantic checker issue's field (e.g. `branchClass`), pinning an entry to one recorded checker defect instead of every future semantic issue on the same records. Text divergences carry no field, so the clause never matches them.

One routing clause sits alongside the constraints: `check=semantic` scopes an entry to the `semantic` subcommand's checker issues; entries without it classify text-parity divergences (`tsv`/`live`) only. An entry never crosses instruments.

## Entry table

| id | status | matcher | evidence |
|---|---|---|---|
| `amx-apple-coprocessor` | expected | `iris.category=amx; oracle=invalid` | iris decodes Apple's undocumented AMX coprocessor instructions (`0x00201000`-magic words in the op0 0-3 reserved tier); llvm-mc has no AMX target and rejects every one. Example: `0x00201000` → iris `ldx x0`, llvm-mc 22.1.8 `invalid instruction encoding`. The AMX decode is validated structurally against the corsix AMX reference, not against llvm-mc. |

## What is not here

**Harvest-era oracle-blind TSV cells.** Rows in `real_text.tsv` files whose expected column was captured at a narrower `-mattr` than the family maximum (each TSV's header comment records its harvest mattr). `iris-parity tsv --reanchor` re-drives every divergent row through llvm-mc at the family's maximal mattr and reports rows where iris matches the live oracle as `oracle-blind`, separately from true divergences. A static catalogue entry would risk masking real regressions on those words.

**SVE/SME/SVE2 encodings.** The `sve` and `sme` families own those tiers, carry their own synthetic corpora, and sweep divergence-free. The `reserved` family covers op0 0, 1 and 3, which are architecturally unallocated apart from Apple's AMX tier. Every family runs its oracle at the same maximal `-mattr` (`+all,+v9.6a`), so oracle and iris never disagree about who decodes what.

**The `LSGoldenCorpusTests` / `DPRGoldenCorpusTests` skip lists** (structured SIMD LD1-LD4/ST1-ST4, MTE tags, MOPS, LS64, LSE128, RPRFM, the PAC DPR tier, RMIF/SETF). Every row they name decodes to the oracle text through the composed dispatcher, and all in-repo synthetics diff clean with no skip filters. The lists survive as harmless over-protection; the parity tool applies none of them.

Oracle version for all evidence here: Homebrew LLVM 22.1.8 (`llvm-mc`), `-triple=arm64-apple-macos`, `-mattr=+all,+v9.6a`.

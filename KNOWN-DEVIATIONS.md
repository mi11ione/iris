# Known Deviations

The catalogue of every expected divergence between Iris and the
`llvm-mc` oracle, with evidence. This file is both documentation and a
machine-readable table: `iris-parity` parses the entry table below and
classifies matching divergences under their entry id, reported on
every run and never gating. Anything the harness reports that is NOT in
this table gates (exit non-zero). The parity contract is zero
unexplained rows.

Two statuses exist:

- `expected`: a by-design gap between Iris's scope and the oracle's
  (or vice versa). Permanent until the scope changes.
- `open-defect`: a recorded Iris bug awaiting a dedicated fix. When
  decode behavior must stay frozen during tooling work, the harness
  catalogues the defect instead of hiding it. The entry MUST be removed
  by the change that fixes it, after which the parity run goes
  divergence-free and stays gating against regressions.

Matcher mini-language (all clauses must hold): `iris.category=<name>` ·
`iris.mnemonic=<name>` · `oracle=invalid` (empty oracle text) ·
`oracle.prefix=<token>` · `encoding.mask=0xMASK:0xVALUE`
(`encoding & MASK == VALUE`) · `field=<name>` (the semantic checker
issue's field, e.g. `branchClass`. The clause pins an entry to ONE
recorded checker defect instead of every future semantic issue on the
same records. Text divergences carry no field, so the clause never
matches them). One routing clause exists alongside the constraints:
`check=semantic` scopes an entry to the `semantic` subcommand's checker
issues, and entries without it classify text-parity divergences
(`tsv`/`live`) only. An entry never crosses instruments. A semantic
deviation must not mask a text divergence, and vice versa.

## Entry table

| id | status | matcher | evidence |
|---|---|---|---|
| `amx-apple-coprocessor` | expected | `iris.category=amx; oracle=invalid` | Iris decodes Apple's undocumented AMX coprocessor instructions (`0x00201000`-magic words in the op0 0-3 reserved tier); llvm-mc has no AMX target support and rejects every one. Example: `0x00201000` → Iris `ldx x0`, llvm-mc 22.1.4 `invalid instruction encoding`. The AMX decode itself is validated structurally against the corsix AMX reference, not against llvm-mc. |

## What is deliberately NOT here

- **Harvest-era oracle-blind TSV cells.** Rows in `real_text.tsv`
  files whose expected column was captured at a narrower `-mattr`
  than the family maximum (the header comment of each TSV records the
  harvest mattr). These are an artifact of the TSV file, handled
  structurally: `iris-parity tsv --reanchor` re-drives every divergent
  row through llvm-mc at the family's maximal mattr and reports rows
  where Iris matches the live oracle as `oracle-blind`, separately from
  true divergences. A static catalogue entry would risk masking real
  regressions on those words.
- **SVE/SME/SVE2 encodings.** Not a deviation. The oracle mattrs for
  the reserved tier deliberately exclude `+sve`/`+sme` (a scope wall at
  this version, stated in the README's Scope section), so oracle and
  Iris agree those words are undefined or rejected. The per-family
  mattrs that do include `+sve`/`+sme` (BES/DPR/LS) carry them only for
  system register coverage inside op0 4-15 partitions, where the parent
  project's exhaustive sweeps proved zero divergence.
- **The legacy deferred-OOS test catalogues**
  (`LSGoldenCorpusTests`/`DPRGoldenCorpusTests` skip lists: structured
  SIMD LD1-LD4/ST1-ST4, MTE tags, MOPS, LS64, LSE128, RPRFM, the PAC
  DPR tier, RMIF/SETF). Verified obsolete: every such row in the
  synthetic corpora now decodes to the oracle text through the composed
  dispatcher (all five in-repo synthetics diff clean with NO skip
  filters). The skip lists are retained in those tests as harmless
  over-protection, and the parity tool applies none of them.

Oracle version for all evidence in this file: Homebrew LLVM 22.1.4
(`llvm-mc`), `-triple=arm64-apple-macos`.

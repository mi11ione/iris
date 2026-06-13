# JSON output

The NDJSON schema behind `iris --json`, the versioned contract for the
command-line tool's machine-readable output.

## The contract

**`schemaVersion`: 1.** This article is the contract for the machine-readable output of the `iris` CLI. Every emitted object carries the `schemaVersion` field, and consumers should gate on it. The schema follows the same text-stability discipline as the library's canonical assembly: within one major schema version, fields are only ever *added*, never renamed, retyped, reordered, or removed. Any breaking change increments `schemaVersion`. Key order within an object is fixed as documented and byte-stable across runs and platforms, so `iris --json` output is safe to diff.

## Stream shape

`--json` selects NDJSON: one self-contained JSON object per line, separated by `\n`, streamed as decode proceeds (no enclosing array, no trailing commas, so `jq`, `python -c`, and line-oriented shell tools consume it directly). Three object kinds exist, discriminated by the `kind` field:

- `"instruction"`: one per decoded record, in address order, sections in load-command order (`iris disasm --json <file>`, `iris decode --json 0x<word>`, `iris decode --json --bytes "…"`).
- `"census"`: exactly one object for the whole input (`iris stats --json <file>`).
- `"function"`: one per function, in address order, sections in load-command order (`iris functions --json <file>`). Each function object wraps its own instruction objects.

Diagnostics never appear on stdout in either mode. They go to stderr (suppressed by `--quiet`).

## kind: "instruction"

Field order is fixed: `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes`, `branchClass`, `memoryAccess`, `ordering`, `flagEffect`, then the optional `branchTarget`, `pcRelativeTarget`, `symbol`, and `targetSymbol` (each present only when resolved), then `isData`, `isUndefined`.

| field | type | meaning |
|---|---|---|
| `schemaVersion` | number | always `1` for this article |
| `kind` | string | `"instruction"` |
| `address` | string | VM address of the record, `0x`-prefixed lowercase hex (string, not number: addresses exceed 2^53) |
| `encoding` | string | the raw little-endian instruction word, `0x` + exactly 8 hex digits. For a truncated tail, the residual bytes zero-extended |
| `mnemonic` | string | canonical mnemonic name (`"add"`, `"b.cond"`). Sentinel records carry the census labels `"undefined"`, `"data"`, `"truncated"` |
| `text` | string | the library's canonical assembly rendering. Branch labels stay in relative `#offset` form (the absolute target is `branchTarget`) |
| `category` | string | top-level decode category, one of: `undefined`, `dataInCodeMarker`, `truncatedTail`, `dataProcessingImmediate`, `branchesExceptionSystem`, `dataProcessingRegister`, `loadsAndStores`, `simdAndFP`, `pointerAuthentication`, `crypto`, `amx`, `memoryTagging` |
| `operands` | string[] | per-operand text fragments split from `text` (commas inside `[…]`/`{…}` do not split). Empty for sentinel records |
| `reads` | string[] | architectural registers read, canonical names (`x0…x30`, `sp`, `v0…v31`), ascending and alias-independent. XZR/WZR never appear |
| `writes` | string[] | architectural registers written, same vocabulary |
| `branchClass` | string | `none`, `direct`, `indirect`, `conditional`, `call`, `return`, `exception` |
| `memoryAccess` | string | `none`, `load`, `store`, `atomic`, `exclusive-load`, `exclusive-store`, `prefetch` |
| `ordering` | string[] | `[]` (relaxed), `["acquire"]`, `["release"]`, or `["acquire","release"]` |
| `flagEffect` | object | `{"reads": "<letters>", "writes": "<letters>"}` where letters are a subset of `nzcv` in that order, with empty strings for no effect |
| `branchTarget` | string? | absolute resolved target of a direct branch (B/BL/B.cond/CBZ/TBZ…), `0x` hex, **absent** for indirect/exception/non-branches |
| `pcRelativeTarget` | string? | absolute PC-relative data address (ADR/ADRP/literal loads/literal prefetch), `0x` hex, **absent** otherwise |
| `symbol` | string? | name of the function containing the record, the label the listing groups under (a symbol-table name, or the `sub_<hex>` form when only `LC_FUNCTION_STARTS` marks the entry). **File mode only**, **absent** in the direct-decode modes (`0x<word>` / `--bytes`), which carry no symbols, and absent for a record no function owns |
| `targetSymbol` | string? | name the `branchTarget` resolves to: the imported function a `__stubs` entry forwards to (matching the listing's `symbol stub for:` annotation), a symbol exactly at the target, or the closest preceding symbol in the same section as `name+0x<delta>`. **File mode only**, **absent** when the target is unresolved or the record does not branch |
| `isData` | bool | `true` iff the word is covered by an `LC_DATA_IN_CODE` span (`category == "dataInCodeMarker"`) |
| `isUndefined` | bool | `true` iff the encoding is unallocated or its extension is absent from the decode features, the explicit "Iris decodes nothing here" witness |

Example (one line, wrapped for reading):

```json
{"schemaVersion":1,"kind":"instruction","address":"0x1000003ac","encoding":"0x97ffffdf",
 "mnemonic":"bl","text":"bl #-132","category":"branchesExceptionSystem","operands":["#-132"],
 "reads":[],"writes":["x30"],"branchClass":"call","memoryAccess":"none","ordering":[],
 "flagEffect":{"reads":"","writes":""},"branchTarget":"0x100000328",
 "symbol":"_caller","targetSymbol":"_callee","isData":false,"isUndefined":false}
```

`text` is the encoding-level disassembly. A direct branch shows the bare relative `bl #-132` there. The resolved targets live in the typed fields: `branchTarget` for control flow, `pcRelativeTarget` for address formation, and `targetSymbol` for the resolved name. Read those, not `text`, to follow an edge.

`flagEffect` carries `reads` and `writes` as compact `nzcv` strings (a subset of the four condition flags, in `nzcv` order, empty for no effect) while the top-level `reads` and `writes` are register-name arrays. The flags are a small fixed four-element set, so a packed-letter string is the natural shape for them. The register sets are open-ended, so they are arrays. This difference is deliberate and the two shapes do not change.

`symbol` and `targetSymbol` arrived after `schemaVersion 1` shipped. They are additive optional fields, exactly what this article's add-only policy permits within a major schema version, so `schemaVersion` stays `1`. A consumer written against the original schema ignores the new keys; a consumer that wants function context reads them when present.

## kind: "census"

Emitted by `iris stats --json <file>`: one object aggregating every decoded record of the input. Field order is fixed: `schemaVersion`, `kind`, `totalWords`, `undefinedWords`, `dataWords`, `truncatedTails`, `extensions`, `categories`, `mnemonics`.

| field | type | meaning |
|---|---|---|
| `totalWords` | number | all records (4-byte words plus a truncated-tail record if present) |
| `undefinedWords` | number | UNDEFINED records |
| `dataWords` | number | data-in-code marker records |
| `truncatedTails` | number | trailing-residual records (0 or 1 per section/stream) |
| `extensions` | object | `{"pointerAuthentication": n, "memoryTagging": n, "amx": n, "crypto": n}`, instruction counts per extension family (PAC counts mnemonic-classified PAC sites, the others count their categories) |
| `categories` | object | category name → count, keys sorted lexicographically |
| `mnemonics` | object | mnemonic name → count, keys sorted lexicographically. Sentinel records are counted in the totals above rather than here |

Example:

```json
{"schemaVersion":1,"kind":"census","totalWords":20,"undefinedWords":0,"dataWords":2,
 "truncatedTails":0,"extensions":{"pointerAuthentication":0,"memoryTagging":0,"amx":0,"crypto":0},
 "categories":{"branchesExceptionSystem":7,"dataInCodeMarker":2,"dataProcessingImmediate":9,
 "dataProcessingRegister":1,"loadsAndStores":1},
 "mnemonics":{"add":2,"adr":1,"adrp":1,"b.cond":1,"br":1,"cmp":1,"ldrb":1,"mov":5,"ret":5}}
```

## kind: "function"

Emitted by `iris functions --json <file>`: one object per function, in address order, sections in load-command order. The right way to get one record per function for an LLM or a call-graph pass, instead of grouping the per-instruction stream by `.symbol` (whose label can extend into trailing padding or a `__stubs` island and so mis-attribute those words to the last function). Each function object owns the `schemaVersion` and wraps its instruction objects.

Field order is fixed: `schemaVersion`, `kind`, `symbol`, `address`, `endAddress`, `instructionCount`, `instructions`.

| field | type | meaning |
|---|---|---|
| `schemaVersion` | number | always `1` for this article |
| `kind` | string | `"function"` |
| `symbol` | string | the function's name: a symbol-table name, or the `sub_<hex>` form when only `LC_FUNCTION_STARTS` marks the entry (a stripped binary). Always present |
| `address` | string | VM address of the function start, `0x` hex. Equal to the first instruction's `address` |
| `endAddress` | string | exclusive end VM address, `0x` hex. The next function start, clamped to the end of the section the function starts in, so the span never reaches into a different section |
| `instructionCount` | number | number of instruction objects in `instructions` |
| `instructions` | object[] | the function's instruction objects in address order, each one a `kind:"instruction"` object exactly as documented above but with the redundant leading `schemaVersion` omitted (the function object carries the version). Every other field is identical, including `symbol` and `targetSymbol`, so a consumer that plucks one out and reinserts `schemaVersion` has a valid instruction record |

Boundaries come from `LC_FUNCTION_STARTS` and section membership only. They are loader data, never control-flow inference, so the carve is the same one the text listing groups under. The `functions` verb reads a Mach-O file. A raw word (`iris decode 0x<word>` or `iris decode --bytes`) carries no function table, so `functions` is one of the file verbs and routes raw words to `decode`.

Example (one line, wrapped for reading, a single-instruction function whose one branch reaches an imported function through a stub):

```json
{"schemaVersion":1,"kind":"function","symbol":"_compare","address":"0x100000410",
 "endAddress":"0x100000414","instructionCount":1,"instructions":[
 {"kind":"instruction","address":"0x100000410","encoding":"0x14000007","mnemonic":"b",
  "text":"b #28","category":"branchesExceptionSystem","operands":["#28"],"reads":[],"writes":[],
  "branchClass":"direct","memoryAccess":"none","ordering":[],"flagEffect":{"reads":"","writes":""},
  "branchTarget":"0x10000042c","symbol":"_compare","targetSymbol":"_strcoll",
  "isData":false,"isUndefined":false}]}
```

## Consuming it

```sh
# every call site of objc_msgSend-like indirect calls
iris disasm --json MyApp | jq -r 'select(.branchClass=="call") | .address'

# PAC adoption check in CI (exit nonzero when absent)
iris stats --json MyApp | jq -e '.extensions.pointerAuthentication > 0'

# one record per function (name, size, instruction count) for an LLM pass
iris functions --json MyApp | jq -c '{symbol, address, endAddress, instructionCount}'

# Python: stream without loading the whole listing
import json, subprocess
proc = subprocess.Popen(["iris", "--json", "MyApp"], stdout=subprocess.PIPE, text=True)
for line in proc.stdout:
    record = json.loads(line)
    if record["isUndefined"]:
        print(record["address"], record["encoding"])
```

String escaping follows JSON exactly (`"`, `\`, `\n`, `\r`, `\t` and `\u00XX` for other control characters). All other characters, including non-ASCII symbol names, pass through as UTF-8. Numbers are decimal integers. Addresses and encodings are hex *strings* by design.

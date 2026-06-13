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

Field order is fixed: `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes`, `branchClass`, `memoryAccess`, `ordering`, `flagEffect`, then the optional `branchTarget`, `pcRelativeTarget`, `symbol`, `targetSymbol`, `referencedSection`, `referencedString`, `referencedSymbol`, and `charLiteral` (each present only when resolved), then `isData`, `isUndefined`.

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
| `referencedSection` | string? | the data section (`__TEXT,__cstring`, `__DATA_CONST,__const`, …) the instruction's formed PC-relative address lands in, the listing's `; <section>` comment. Covers a single ADR / literal load and the local `adrp`+`add` / `adrp`+`ldr` idiom (the page base from the `adrp`, the low offset from this instruction). **File mode only**, **absent** when the target is in no data section |
| `referencedString` | string? | the NUL-terminated C string at the target, present only when `referencedSection` is a cstring-literal section and the bytes read back (the listing's `; "the string"`). JSON-escaped like every other string here, and not length-capped (the listing's `…` truncation is presentation only). An empty C string at the target reads back as `""`, a present-but-empty value, not an absent field |
| `referencedSymbol` | string? | the data symbol the target resolves to: a name exactly at it, or `name+0x<delta>` for a target past a symbol in the same data section (the listing's `; _name`). **File mode only**, **absent** when no symbol names the target |
| `charLiteral` | string? | the single printable-ASCII character (`0x20`…`0x7e`) an immediate names, for the comparison / arithmetic / move mnemonics where a byte-sized constant reads as a character (`cmp w0, #65` → `"A"`), the listing's `; 'c'`. Stack-pointer arithmetic is excluded (frame management, not a character). Present in every mode (it needs no symbols), **absent** otherwise |
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

`referencedSection`, `referencedString`, `referencedSymbol`, and `charLiteral` are the referenced-data fields, the same additive treatment. They surface what an address-forming instruction points at, which `text` alone does not name: `text` shows `add x0, x0, #1256`, the fields show that the formed address lands in `__TEXT,__cstring` and reads back `"hello, %s!\n"`. The recognition is the local `adrp`+`add` / `adrp`+`ldr` idiom (and the single literal loads), the same one `otool` and `llvm-objdump` annotate, never broader value tracking. `charLiteral` is the only one present in the direct-decode modes, since it reads an immediate rather than the binary's sections.

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

Field order is fixed: `schemaVersion`, `kind`, `symbol`, `address`, `endAddress`, `instructionCount`, `usesPAC`, `instructions`.

| field | type | meaning |
|---|---|---|
| `schemaVersion` | number | always `1` for this article |
| `kind` | string | `"function"` |
| `symbol` | string | the function's name: a symbol-table name, or the `sub_<hex>` form when only `LC_FUNCTION_STARTS` marks the entry (a stripped binary). Always present |
| `address` | string | VM address of the function start, `0x` hex. Equal to the first instruction's `address` |
| `endAddress` | string | exclusive end VM address, `0x` hex. The next function start, clamped to the end of the section the function starts in, so the span never reaches into a different section |
| `instructionCount` | number | number of instruction objects in `instructions` |
| `usesPAC` | bool | true when any instruction in the function uses pointer authentication, the same classification the `functions` table prints in its PAC column. Always present in the full form, so a per-function PAC gate reads it directly without scanning the instruction array |
| `instructions` | object[] | the function's instruction objects in address order, each one a `kind:"instruction"` object exactly as documented above but with the redundant leading `schemaVersion` omitted (the function object carries the version). Every other field is identical, including `symbol` and `targetSymbol`, so a consumer that plucks one out and reinserts `schemaVersion` has a valid instruction record |

Boundaries come from `LC_FUNCTION_STARTS` and section membership only. They are loader data, never control-flow inference, so the carve is the same one the text listing groups under. The `functions` verb reads a Mach-O file. A raw word (`iris decode 0x<word>` or `iris decode --bytes`) carries no function table, so `functions` is one of the file verbs and routes raw words to `decode`.

Example (one line, wrapped for reading, a single-instruction function whose one branch reaches an imported function through a stub):

```json
{"schemaVersion":1,"kind":"function","symbol":"_compare","address":"0x100000410",
 "endAddress":"0x100000414","instructionCount":1,"usesPAC":false,"instructions":[
 {"kind":"instruction","address":"0x100000410","encoding":"0x14000007","mnemonic":"b",
  "text":"b #28","category":"branchesExceptionSystem","operands":["#28"],"reads":[],"writes":[],
  "branchClass":"direct","memoryAccess":"none","ordering":[],"flagEffect":{"reads":"","writes":""},
  "branchTarget":"0x10000042c","symbol":"_compare","targetSymbol":"_strcoll",
  "isData":false,"isUndefined":false}]}
```

## The --slim projection

`--slim`, valid wherever `--json` is, emits the same data with the zero-signal constants dropped. It is opt-in and never changes the default `--json` output. The default per-instruction object is heavier than the `--semantics` text line for the same instruction, and about half of that weight is fields that repeat unchanged on every line. `--slim` is the projection for a model payload or any consumer paying per token, where the verbose default is the wrong default.

What it drops, per instruction object:

- `kind` and `schemaVersion`. The stream is selected by the verb, so the discriminator and the version carry no per-line signal. (A consumer that needs the version reads it from the article, or pins the `iris` release.)
- A field that is empty or false: `ordering` when relaxed, `flagEffect` when no flag moves, `branchClass` / `memoryAccess` when `none`, `isData` / `isUndefined` when false. The remaining presence of `isData` / `isUndefined` is the witness: a slim line carries them **only when true**.
- In `functions --json --slim`, the per-instruction `symbol`. The function object already names the function, so repeating it on every nested instruction is pure boilerplate.

What it keeps, every signal-bearing field in the same fixed order: `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes` (kept even when empty, an empty `reads` is "reads nothing"), a non-`none` `branchClass` / `memoryAccess`, a non-empty `ordering` / `flagEffect`, a present `branchTarget` / `pcRelativeTarget` / `symbol` (stream only) / `targetSymbol`, the referenced-data fields, `charLiteral`, and a true `isData` / `isUndefined`. A kept field's position never shifts, so a slim line is the default line with the dropped keys removed, nothing reordered.

The `functions --json --slim` object drops the same two constants (`kind`, `schemaVersion`); it keeps `symbol`, `address`, `endAddress`, `instructionCount` (all signal), keeps `usesPAC` only when the function uses pointer authentication (the drop-false rule, so a present `usesPAC` always means true), and is unmistakably a function (it is the only shape carrying `instructions`). Because slim drops the constant `kind`, discriminate a slim function object by structure, `has(instructions)` in jq, rather than `kind`. `stats --json --slim` drops the census object's `kind` and `schemaVersion` only, since every count it carries is signal (a zero `pointerAuthentication` is exactly what a CI gate reads).

Example, one slim instruction line (a call, wrapped for reading):

```json
{"address":"0x1000003ac","encoding":"0x97ffffdf","mnemonic":"bl","text":"bl #-132",
 "category":"branchesExceptionSystem","operands":["#-132"],"reads":[],"writes":["x30"],
 "branchClass":"call","branchTarget":"0x100000328","symbol":"_helper","targetSymbol":"_add42"}
```

The default form of the same line carries `schemaVersion`, `kind`, the `none` / `[]` / empty fields, and the false `isData` / `isUndefined` in addition. Read `--slim` for size, the default for a self-describing record.

```sh
# the model payload: one slim object per function
iris functions --json --slim MyApp
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

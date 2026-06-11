# JSON output

The NDJSON schema behind `iris --json`, the versioned contract for the
command-line tool's machine-readable output.

## The contract

**`schemaVersion`: 1.** This article is the contract for the machine-readable output of the `iris` CLI. Every emitted object carries the `schemaVersion` field, and consumers should gate on it. The schema follows the same text-stability discipline as the library's canonical assembly: within one major schema version, fields are only ever *added*, never renamed, retyped, reordered, or removed. Any breaking change increments `schemaVersion`. Key order within an object is fixed as documented and byte-stable across runs and platforms, so `iris --json` output is safe to diff.

## Stream shape

`--json` selects NDJSON: one self-contained JSON object per line, separated by `\n`, streamed as decode proceeds (no enclosing array, no trailing commas, so `jq`, `python -c`, and line-oriented shell tools consume it directly). Two object kinds exist, discriminated by the `kind` field:

- `"instruction"`: one per decoded record, in address order, sections in load-command order (`iris --json <file>`, `iris --json 0x<word>`, `iris --json --bytes "…"`).
- `"census"`: exactly one object for the whole input (`iris --json --stats …`).

Diagnostics never appear on stdout in either mode. They go to stderr (suppressed by `--quiet`).

## kind: "instruction"

Field order is fixed: `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes`, `branchClass`, `memoryAccess`, `ordering`, `flagEffect`, then the optional `branchTarget` and `pcRelativeTarget` (each present only when resolved), then `isData`, `isUndefined`.

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
| `isData` | bool | `true` iff the word is covered by an `LC_DATA_IN_CODE` span (`category == "dataInCodeMarker"`) |
| `isUndefined` | bool | `true` iff the encoding is unallocated or its extension is absent from the decode features, the explicit "Iris decodes nothing here" witness |

Example (one line, wrapped for reading):

```json
{"schemaVersion":1,"kind":"instruction","address":"0x1000003ac","encoding":"0x97ffffdf",
 "mnemonic":"bl","text":"bl #-132","category":"branchesExceptionSystem","operands":["#-132"],
 "reads":[],"writes":["x30"],"branchClass":"call","memoryAccess":"none","ordering":[],
 "flagEffect":{"reads":"","writes":""},"branchTarget":"0x100000328",
 "isData":false,"isUndefined":false}
```

## kind: "census"

Emitted by `--stats --json`: one object aggregating every decoded record of the input. Field order is fixed: `schemaVersion`, `kind`, `totalWords`, `undefinedWords`, `dataWords`, `truncatedTails`, `extensions`, `categories`, `mnemonics`.

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

## Consuming it

```sh
# every call site of objc_msgSend-like indirect calls
iris --json MyApp | jq -r 'select(.branchClass=="call") | .address'

# PAC adoption check in CI (exit nonzero when absent)
iris --json --stats MyApp | jq -e '.extensions.pointerAuthentication > 0'

# Python: stream without loading the whole listing
import json, subprocess
proc = subprocess.Popen(["iris", "--json", "MyApp"], stdout=subprocess.PIPE, text=True)
for line in proc.stdout:
    record = json.loads(line)
    if record["isUndefined"]:
        print(record["address"], record["encoding"])
```

String escaping follows JSON exactly (`"`, `\`, `\n`, `\r`, `\t` and `\u00XX` for other control characters). All other characters, including non-ASCII symbol names, pass through as UTF-8. Numbers are decimal integers. Addresses and encodings are hex *strings* by design.

# JSON output

The NDJSON schema behind `iris --json`.

## The contract

**`schemaVersion`: 1.** Every emitted object carries it. Within one major version fields are only added, never renamed, retyped, reordered or removed; a breaking change increments it. Key order is fixed and byte-stable across runs and platforms, so the output is safe to diff.

`--json` emits one self-contained object per line, streamed as decode proceeds, with no enclosing array and no trailing commas. Three kinds exist, discriminated by `kind`:

- `"instruction"`: one per decoded record, address order, sections in load-command order (`iris disasm --json`, `iris decode --json`).
- `"census"`: one object for the whole input (`iris stats --json`).
- `"function"`: one per function, address order (`iris functions --json`), wrapping its own instruction objects.

Diagnostics go to stderr, never stdout, and `--quiet` suppresses them.

## kind: "instruction"

Field order: `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes`, `branchClass`, `memoryAccess`, `ordering`, `flagEffect`, then the optional `scalableReads`, `scalableWrites`, `scalableEffect`, `branchTarget`, `pcRelativeTarget`, `symbol`, `targetSymbol`, `referencedSection`, `referencedString`, `referencedSymbol`, `charLiteral`, then `isData`, `isUndefined`.

| field | type | meaning |
|---|---|---|
| `address` | string | VM address, `0x` lowercase hex. A string because addresses exceed 2^53. `iris decode` counts from the `--at` base address, 0 when it is absent |
| `encoding` | string | the raw little-endian word, `0x` + 8 hex digits; a truncated tail zero-extends its residual bytes |
| `mnemonic` | string | canonical name (`"add"`, `"b.cond"`). Sentinels carry `"undefined"`, `"data"`, `"truncated"` |
| `text` | string | canonical assembly. Branch labels stay relative; the absolute target is `branchTarget` |
| `category` | string | `undefined`, `dataInCodeMarker`, `truncatedTail`, `dataProcessingImmediate`, `branchesExceptionSystem`, `dataProcessingRegister`, `loadsAndStores`, `simdAndFP`, `pointerAuthentication`, `crypto`, `amx`, `memoryTagging`, `sve`, `sme` |
| `operands` | string[] | per-operand fragments split from `text`; commas inside `[…]`/`{…}` do not split. Empty for sentinels |
| `reads` | string[] | architectural registers read, ascending and alias-independent (`x0…x30`, `sp`, `v0…v31`). XZR/WZR never appear; SVE `Zn` appear as their `v` aliases |
| `writes` | string[] | registers written, same vocabulary |
| `branchClass` | string | `none`, `direct`, `indirect`, `conditional`, `call`, `return`, `exception` |
| `memoryAccess` | string | `none`, `load`, `store`, `atomic`, `exclusive-load`, `exclusive-store`, `prefetch` |
| `ordering` | string[] | `[]`, `["acquire"]`, `["release"]`, or both |
| `flagEffect` | object | `{"reads": "<letters>", "writes": "<letters>"}`, a subset of `nzcv` in that order |
| `branchTarget` | string? | absolute target of a direct branch. Absent for indirect, exception and non-branches |
| `pcRelativeTarget` | string? | absolute PC-relative data address (ADR/ADRP/literal loads). Absent otherwise |
| `symbol` | string? | the containing function's name, or `sub_<hex>` when only `LC_FUNCTION_STARTS` marks the entry. File mode only |
| `targetSymbol` | string? | what `branchTarget` resolves to: the imported function a `__stubs` entry forwards to, a symbol exactly at the target, or `name+0x<delta>` for the closest preceding symbol in the same section. File mode only |
| `referencedSection` | string? | the data section the formed PC-relative address lands in. Covers a single ADR or literal load and the local `adrp`+`add` / `adrp`+`ldr` idiom. File mode only |
| `referencedString` | string? | the NUL-terminated C string at the target, when `referencedSection` is a cstring section and the bytes read back. Not length-capped; an empty string at the target reads back as `""` |
| `referencedSymbol` | string? | the data symbol at the target, or `name+0x<delta>` past one in the same section. File mode only |
| `charLiteral` | string? | the printable-ASCII character an immediate names (`cmp w0, #65` → `"A"`), for the mnemonics where a byte-sized constant reads as a character. Stack-pointer arithmetic is excluded. Present in every mode |
| `scalableReads` | object? | SVE/SME state read, absent when none. Members appear when non-empty: `predicates` (`p0`…`p15`), `za` (16-bit `.Q`-position mask, `0x` + 4 hex digits), `ffr`, `zt0` |
| `scalableWrites` | object? | SVE/SME state written, same shape and rule |
| `scalableEffect` | string[]? | `partial-write`, `reads-streaming-mode`, `writes-streaming-mode`, `writes-za-enable`, `first-faulting`, `non-faulting`, `non-temporal`, in that order. Absent when none |
| `isData` | bool | true when the word is covered by an `LC_DATA_IN_CODE` span |
| `isUndefined` | bool | true when the encoding is unallocated or its extension is absent from the decode features |

```json
{"schemaVersion":1,"kind":"instruction","address":"0x1000003ac","encoding":"0x97ffffdf",
 "mnemonic":"bl","text":"bl #-132","category":"branchesExceptionSystem","operands":["#-132"],
 "reads":[],"writes":["x30"],"branchClass":"call","memoryAccess":"none","ordering":[],
 "flagEffect":{"reads":"","writes":""},"branchTarget":"0x100000328",
 "symbol":"_caller","targetSymbol":"_callee","isData":false,"isUndefined":false}
```

`text` is the encoding-level disassembly, so a direct branch shows the bare relative `bl #-132`. Follow an edge through `branchTarget`, `pcRelativeTarget` and `targetSymbol`, not `text`.

Raw words carry no container to take addresses from, so `iris decode` counts from 0 unless `--at` gives the window its base; `address`, `branchTarget` and `pcRelativeTarget` all resolve against it, which is what makes a window lifted out of a core dump readable.

```sh
$ iris decode --json --slim --at 0xfffffe0007b3c000 --bytes "0d fe ff 17"
{"address":"0xfffffe0007b3c000","encoding":"0x17fffe0d","mnemonic":"b","text":"b #-1996",
 "category":"branchesExceptionSystem","operands":["#-1996"],"reads":[],"writes":[],
 "branchClass":"direct","branchTarget":"0xfffffe0007b3b834"}
```

Scalable instructions emit ordinary instruction objects: `category` is `sve` or `sme`, `text` and `operands` carry the full syntax, and `Zn` vectors appear in `reads`/`writes` as `v` aliases. Predicates, FFR, `ZA` and `ZT0` live in `scalableReads`/`scalableWrites`, all absent on a base-ISA line.

```json
{"…":"…","category":"sme","text":"fmopa za0.s, p7/m, p7/m, z0.s, z0.s",
 "reads":["v0"],"writes":[],
 "scalableReads":{"predicates":["p7"],"za":"0x1111"},
 "scalableWrites":{"za":"0x1111"},
 "scalableEffect":["partial-write","reads-streaming-mode"]}
```

`za` is a mask, not a tile name: a tile occupies the `.Q` positions `{ q : q mod tileCount == n }`, many tile/element pairs share a mask, and a union of accesses has no single name. `za0.s` is tile 0 of the four `.S` tiers, positions 0/4/8/12, hence `0x1111`. Two accesses touch the same storage when their masks intersect.

The referenced-data fields surface what an address-forming instruction points at: `text` shows `add x0, x0, #1256`, the fields show the address landing in `__TEXT,__cstring` and reading back `"hello, %s!\n"`. Recognition covers the local `adrp` idioms and single literal loads, what `otool` and `llvm-objdump` annotate, never broader value tracking.

## kind: "census"

One object aggregating every decoded record. Field order: `schemaVersion`, `kind`, `totalWords`, `undefinedWords`, `dataWords`, `truncatedTails`, `extensions`, `categories`, `mnemonics`.

| field | type | meaning |
|---|---|---|
| `totalWords` | number | all records, including a truncated-tail record if present |
| `undefinedWords` | number | UNDEFINED records |
| `dataWords` | number | data-in-code marker records |
| `truncatedTails` | number | trailing-residual records, 0 or 1 per stream |
| `extensions` | object | `{"pointerAuthentication": n, "memoryTagging": n, "amx": n, "crypto": n}`. PAC counts mnemonic-classified sites, the rest count categories |
| `categories` | object | category name → count, keys sorted |
| `mnemonics` | object | mnemonic name → count, keys sorted. Sentinels are counted in the totals above |

```json
{"schemaVersion":1,"kind":"census","totalWords":20,"undefinedWords":0,"dataWords":2,
 "truncatedTails":0,"extensions":{"pointerAuthentication":0,"memoryTagging":0,"amx":0,"crypto":0},
 "categories":{"branchesExceptionSystem":7,"dataInCodeMarker":2,"dataProcessingImmediate":9,
 "dataProcessingRegister":1,"loadsAndStores":1},
 "mnemonics":{"add":2,"adr":1,"adrp":1,"b.cond":1,"br":1,"cmp":1,"ldrb":1,"mov":5,"ret":5}}
```

## kind: "function"

One object per function, address order, each owning the `schemaVersion` and wrapping its instruction objects. This is how to get one record per function: grouping the per-instruction stream by `.symbol` can sweep trailing padding or a `__stubs` island into the last function.

Field order: `schemaVersion`, `kind`, `symbol`, `address`, `endAddress`, `instructionCount`, `usesPAC`, `instructions`.

| field | type | meaning |
|---|---|---|
| `symbol` | string | the function's name, or `sub_<hex>` in a stripped binary. Always present |
| `address` | string | function start, equal to the first instruction's `address` |
| `endAddress` | string | exclusive end: the next function start, clamped to the end of the section the function starts in |
| `instructionCount` | number | number of entries in `instructions` |
| `usesPAC` | bool | true when any instruction uses pointer authentication, so a per-function PAC gate reads it without scanning the array |
| `instructions` | object[] | the function's instruction objects in address order, each as documented above minus the leading `schemaVersion`. Every other field is identical |

Boundaries come from `LC_FUNCTION_STARTS` and section membership, never control-flow inference, so the carve matches what the text listing groups under. A raw word carries no function table, so `functions` is a file verb and routes raw words to `decode`.

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

`--slim` is valid wherever `--json` is and never changes the default output. About half a default object's weight is fields repeating unchanged on every line.

It drops `kind` and `schemaVersion`, since the verb selects the stream; anything empty or false (`ordering` when relaxed, `flagEffect` when no flag moves, `branchClass`/`memoryAccess` when `none`, `isData`/`isUndefined` when false), so their presence is the witness; and the per-instruction `symbol` in `functions --json --slim`, which the function object already names.

It keeps, in the same fixed order: `address`, `encoding`, `mnemonic`, `text`, `category`, `operands`, `reads`, `writes` (even when empty — an empty `reads` means it reads nothing), a non-`none` `branchClass`/`memoryAccess`, a non-empty `ordering`/`flagEffect`, the scalable fields, a present `branchTarget`/`pcRelativeTarget`/`symbol`/`targetSymbol`, the referenced-data fields, `charLiteral`, and a true `isData`/`isUndefined`. No kept field shifts position, so a slim line is the default line with keys removed.

The slim function object keeps `symbol`, `address`, `endAddress`, `instructionCount`, and `usesPAC` only when true. Since slim drops `kind`, discriminate a slim function object by structure (`has(instructions)` in jq). `stats --json --slim` drops only the two constants: every count it carries is signal, since a zero `pointerAuthentication` is exactly what a CI gate reads.

```json
{"address":"0x1000003ac","encoding":"0x97ffffdf","mnemonic":"bl","text":"bl #-132",
 "category":"branchesExceptionSystem","operands":["#-132"],"reads":[],"writes":["x30"],
 "branchClass":"call","branchTarget":"0x100000328","symbol":"_helper","targetSymbol":"_add42"}
```

## Consuming it

```sh
# every call site
iris disasm --json MyApp | jq -r 'select(.branchClass=="call") | .address'

# PAC adoption check in CI (exit nonzero when absent)
iris stats --json MyApp | jq -e '.extensions.pointerAuthentication > 0'

# one record per function for an LLM pass
iris functions --json --slim MyApp | jq -c '{symbol, address, endAddress, instructionCount}'

# Python: stream without loading the whole listing
import json, subprocess
proc = subprocess.Popen(["iris", "--json", "MyApp"], stdout=subprocess.PIPE, text=True)
for line in proc.stdout:
    record = json.loads(line)
    if record["isUndefined"]:
        print(record["address"], record["encoding"])
```

String escaping follows JSON exactly (`"`, `\`, `\n`, `\r`, `\t`, `\u00XX` for other control characters). Other characters, non-ASCII symbol names included, pass through as UTF-8. Numbers are decimal integers; addresses and encodings are hex strings.

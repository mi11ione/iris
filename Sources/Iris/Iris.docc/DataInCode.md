# Data in code

Compilers embed data inside code sections. Iris marks those words as data
instead of decoding garbage. Only your loader can say where they are.

## Overview

Jump tables, branch islands' literal pools, and padding live *inside*
`__text` in real binaries. Those bytes are not instructions, and decoding
them as instructions produces well-formed nonsense, misleading mnemonics
with meaningless operands. The catch is that **data-in-code placement is
loader-level knowledge**. It cannot be recovered from the bytes alone. On
Mach-O it lives in the `LC_DATA_IN_CODE` load command, and other containers
have their own conventions.

Iris's seam is explicit: the caller passes
``DataInCodeSpan`` values into
`InstructionStream.init(bytes:at:features:dataInCode:)`, and every word a
span covers becomes a data-marker record rather than a decoded instruction.

## Spans

A span is `(offset, length, kind)` in **buffer-offset space**, relative to
the start of the bytes you passed rather than VM addresses. The kinds mirror
Mach-O's `DICE_KIND_*` values (`data`, jump tables by element width,
absolute jump tables), with unknown raw values preserved round-trip:

```swift
let bytes: [UInt8] = [0x00, 0x00, 0x80, 0xD2,     // mov x0, #0
                      0xEF, 0xBE, 0xAD, 0xDE,     // jump-table bytes, not code
                      0xC0, 0x03, 0x5F, 0xD6]     // ret
let stream = InstructionStream(
    bytes: bytes,
    at: 0x1_0000_0000,
    dataInCode: [DataInCodeSpan(offset: 4, length: 4, kind: .jumpTable32)]
)
for instruction in stream {
    print(instruction.text)
}
// mov x0, #0
// .long 0xdeadbeef
// ret
```

## What marking does

A covered word's record carries ``Category/dataInCodeMarker``, an empty
operand list, and the raw word preserved in its encoding. Its text renders
as `.long 0x<hex>`. A span that begins mid-word still marks that whole word.
A word that is partly data is not an instruction. The stream also echoes
each intersecting span as a
``Diagnostic/Kind/dataInCodeSpanEncountered(kind:offset:length:)``
diagnostic, so provenance survives even where listings are not rendered:

```swift
print(stream[1].category == .dataInCodeMarker)    // true
print(stream[1].operands.isEmpty)                 // true
print(stream.diagnostics.count)                   // 1 (the span echo)
```

Spans that lie partly or wholly outside the buffer are clamped to it.
Zero-length spans still mark the word containing their offset, matching the
convention real linkers emit.

## Who recovers the spans

If you consume Mach-O binaries through the `iris` command-line tool, this is
automatic: the CLI walks `LC_DATA_IN_CODE` and passes the spans down, and
listings annotate marked words with their kinds (`; data-in-code
(jump-table-32)`). Library callers with their own loader do what the CLI
does internally: read the container's data-in-code table, convert entries to
buffer offsets relative to the section being decoded, and pass them to the
initializer. Callers with no such table (crash buffers, JIT regions) pass
nothing and accept the honest default: every word decodes, and genuinely
non-code words decode to whatever they are, including UNDEFINED.

The principle is the project's honesty rule: Iris never guesses where data
hides. It either knows (you told it) or decodes the word and tells you
exactly what that word is.

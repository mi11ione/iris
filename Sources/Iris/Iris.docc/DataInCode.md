# Data in code

## Overview

Jump tables, literal pools and padding live inside `__text` in real binaries. Decoding them as instructions produces well-formed nonsense.

Their placement cannot be recovered from the bytes alone. On Mach-O it lives in the `LC_DATA_IN_CODE` load command; other containers have their own conventions. So the caller passes ``DataInCodeSpan`` values into `InstructionStream.init(bytes:at:features:dataInCode:)`, and every word a span covers becomes a data-marker record.

## Spans

A span is `(offset, length, kind)` in buffer-offset space, relative to the bytes you passed, not VM addresses. The kinds mirror Mach-O's `DICE_KIND_*` values, with unknown raw values preserved round-trip.

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

A covered word's record carries ``Category/dataInCodeMarker``, an empty operand list and the raw word in its encoding, rendering as `.long 0x<hex>`. A span beginning mid-word marks that whole word. Each intersecting span is echoed as a ``Diagnostic/Kind/dataInCodeSpanEncountered(kind:offset:length:)``, so provenance survives where listings are not rendered.

```swift
print(stream[1].category == .dataInCodeMarker)    // true
print(stream[1].operands.isEmpty)                 // true
print(stream.diagnostics.count)                   // 1
```

Spans partly or wholly outside the buffer are clamped to it. Zero-length spans mark the word containing their offset, matching what real linkers emit.

## Who recovers the spans

Through the `iris` command-line tool this is automatic: it walks `LC_DATA_IN_CODE`, passes the spans down, and annotates marked words with their kinds (`; data-in-code (jump-table-32)`).

Library callers with their own loader do the same: read the container's table, convert entries to buffer offsets relative to the section being decoded, pass them in. Callers with no such table (crash buffers, JIT regions) pass nothing, and every word decodes to whatever it is, UNDEFINED included.

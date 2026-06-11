# Disassembling with your own loader

Feed Iris bytes from any container (Mach-O, ELF, a crash buffer, a JIT
region) and get packed, address-indexed, semantically classified
instructions back.

## Overview

The library's bulk tier is deliberately **bytes-in**: Iris does not parse
executable containers (that wall is documented in <doc:ScopeAndGuarantees>.
The `iris` command-line tool has its own internal Mach-O walker, which is
not library API). Your loader, whatever it is, owns file formats, segment
mapping, and architecture selection, and hands Iris four things:

```swift
func disassemble(_ textSection: UnsafeRawBufferPointer) -> InstructionStream {
    InstructionStream(
        bytes: textSection,           // the section's raw bytes
        at: 0x1_0000_4000,            // its VM base address
        features: .arm64e,            // extensions implied by the slice
        dataInCode: []                // loader-recovered data spans (see Data in code)
    )
}
```

Decode is a pure function of exactly those four inputs. The
`UnsafeRawBufferPointer` entry is zero-copy (point it at your mapped file),
and an `[UInt8]` convenience initializer delegates to it. Map your loader's
architecture knowledge to ``Features``: an `arm64e` slice means
``Features/arm64e``, and plain `arm64` means the empty set.

## What a stream gives you

``InstructionStream`` is a `RandomAccessCollection` of ``Instruction``
values, one per 4-byte word, plus one truncated-tail record if the buffer
length is not a multiple of 4 (nothing is silently dropped). Iteration forms
ergonomic views over packed storage with zero heap allocation:

```swift
let bytes: [UInt8] = [0xFD, 0x7B, 0xBF, 0xA9,     // stp x29, x30, [sp, #-16]!
                      0xFD, 0x03, 0x00, 0x91,     // mov x29, sp
                      0x00, 0x00, 0x00, 0x94,     // bl #0
                      0xC0, 0x03, 0x5F, 0xD6]     // ret
let stream = InstructionStream(bytes: bytes, at: 0x1_0000_4000)

var callSites: [UInt64] = []
for instruction in stream where instruction.isCall {
    callSites.append(instruction.address)
}
print(callSites.map { String($0, radix: 16) })    // ["100004008"]
```

Address lookup is constant-time arithmetic.
``InstructionStream/instruction(at:)`` requires a record's start address.
``InstructionStream/instruction(containing:)`` rounds an unaligned address
down to its word, the crash-pipeline idiom:

```swift
if let faulting = stream.instruction(containing: 0x1_0000_4006) {
    print(faulting.text)                          // "mov x29, sp"
}
print(stream[address: 0x1_0000_400C]?.text ?? "-")  // "ret"
```

Diagnostics (data-in-code spans encountered, address-space wrap) are typed
values on ``InstructionStream/diagnostics``, never silent and never fatal.

## The three access tiers

The stream stores records in a flat 40-byte-per-instruction array with one
shared operand buffer. That layout is the performance architecture, and all
three access tiers are public API.

The **ergonomic tier** is ``Instruction``: full semantics, text, resolved
targets. Use it everywhere that is not a measured hot loop.

The **session tier** is ``InstructionStream/withSession(_:)``: it pins the
buffers once and serves ``BorrowedInstruction`` views with no per-element
reference counting: stable nanosecond-scale lookups and walks regardless of
what the optimizer can prove at your call site. Use it for hot loops that
touch operands:

```swift
let stores = stream.withSession { session -> Int in
    var stores = 0
    for view in session where view.record.memoryAccess == .store {
        stores += 1
    }
    return stores
}
print(stores)                                     // 1 (the stp)
```

The closure scope is the safety contract: borrowed views must not escape it
(the rules are documented on ``InstructionStream/withSession(_:)``).

The **raw tier** is ``InstructionStream/records``, the packed
``InstructionRecord`` array itself, for scans that need only record fields
at index-arithmetic cost:

```swift
var undefinedWords = 0
for record in stream.records where record.category == .undefined {
    undefinedWords += 1
}
print(undefinedWords)                             // 0
```

## Decoding around an arbitrary PC

Streams need no section discipline. A window around a faulting PC works the
same way. Decode the window at the address your loader knows, then ask for
the faulting instruction:

```swift
let pc: UInt64 = 0x1_0000_4008
let window = InstructionStream(bytes: bytes, at: pc &- 8)
if let at = window.instruction(at: pc) {
    print("\(at.text) reads \(at.semanticReads.map(\.name).joined(separator: ", "))")
    // "bl #0 reads " (bl reads no general registers, it writes x30)
}
```

Buffers whose `baseAddress` is near the top of the address space wrap modulo
2^64 by the documented address model: decode stays total, every record is
reachable at the address it carries, and construction surfaces the wrap as a
``Diagnostic/Kind/addressSpaceWrapped(offset:)`` diagnostic.

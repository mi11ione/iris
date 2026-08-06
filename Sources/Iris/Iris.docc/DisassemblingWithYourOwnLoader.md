# Disassembling with your own loader

Feed iris bytes from any container — Mach-O, ELF, a crash buffer, a JIT region — and get packed, address-indexed, semantically classified instructions back.

## Overview

The bulk tier is bytes-in: iris does not parse executable containers, and the command-line tool's Mach-O walker is not library API. Your loader owns file formats, segment mapping and architecture selection, and hands iris four things:

```swift
func disassemble(_ textSection: UnsafeRawBufferPointer) -> InstructionStream {
    InstructionStream(
        bytes: textSection,           // the section's raw bytes
        at: 0x1_0000_4000,            // its VM base address
        features: .arm64e,            // extensions implied by the slice
        dataInCode: []                // loader-recovered spans (see Data in code)
    )
}
```

Decode is a pure function of exactly those four inputs. The `UnsafeRawBufferPointer` entry is zero-copy, so point it at your mapped file; an `[UInt8]` convenience initializer delegates to it. An `arm64e` slice means ``Features/arm64e``, plain `arm64` the empty set.

## What a stream gives you

``InstructionStream`` is a `RandomAccessCollection` of ``Instruction`` values, one per 4-byte word, plus one truncated-tail record when the buffer length is not a multiple of 4. Iteration forms ergonomic views over packed storage with zero heap allocation.

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

Address lookup is constant-time arithmetic. ``InstructionStream/instruction(at:)`` requires a record's start address; ``InstructionStream/instruction(containing:)`` rounds an unaligned address down to its word, which is the crash-pipeline idiom.

```swift
if let faulting = stream.instruction(containing: 0x1_0000_4006) {
    print(faulting.text)                          // "mov x29, sp"
}
print(stream[address: 0x1_0000_400C]?.text ?? "-")  // "ret"
```

Data-in-code spans encountered and address-space wrap surface on ``InstructionStream/diagnostics``.

## The three access tiers

The stream stores records in a flat 57-byte-per-instruction array with one shared operand buffer. All three tiers over it are public API.

``Instruction`` is the ergonomic tier: full semantics, text, resolved targets. Use it everywhere that is not a measured hot loop.

``InstructionStream/withSession(_:)`` pins the buffers once and serves ``BorrowedInstruction`` views with no per-element reference counting, giving stable nanosecond-scale lookups and walks regardless of what the optimizer can prove at your call site. Use it for hot loops that touch operands.

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

That example reaches into ``BorrowedInstruction/record`` only because it wants the exact ``MemoryAccess`` case. The borrowed view carries the projections directly — ``BorrowedInstruction/isCall``, `readsMemory`, `branchTarget`, the register sets — so a call-graph or dataflow pass never needs `record`. Borrowed views must not escape the closure; the rules are on ``InstructionStream/withSession(_:)``.

``InstructionStream/records`` is the raw tier, the packed ``InstructionRecord`` array itself, for scans needing only record fields at index-arithmetic cost.

```swift
var undefinedWords = 0
for record in stream.records where record.category == .undefined {
    undefinedWords += 1
}
print(undefinedWords)                             // 0
```

## Decoding around an arbitrary PC

A window around a faulting PC works the same way. Decode it at the address your loader knows, then ask for the faulting instruction.

```swift
let pc: UInt64 = 0x1_0000_4008
let window = InstructionStream(bytes: bytes, at: pc &- 8)
if let at = window.instruction(at: pc) {
    print("\(at.text) reads \(at.semanticReads.map(\.name).joined(separator: ", "))")
    // "bl #0 reads " (bl reads no general registers, it writes x30)
}
```

A `baseAddress` near the top of the address space wraps modulo 2^64: decode stays total, every record is reachable at the address it carries, and construction surfaces the wrap as a ``Diagnostic/Kind/addressSpaceWrapped(offset:)``.

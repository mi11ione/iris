# Decode your first instruction

## Overview

The smallest entry point is the module-scope ``decode(_:at:features:)``: one little-endian 4-byte word in, one ``Instruction`` out.

```swift
import Iris

let instruction = decode(0xD503201F)
print(instruction.text)            // "nop"
```

Decode is total. Every possible 32-bit word produces a well-formed ``Instruction``; unknown encodings return a record whose ``Instruction/isUndefined`` is `true`, with the raw word preserved in ``Instruction/encoding`` and a text rendering of `.long 0x<hex>`.

```swift
let mystery = decode(0x00BADBAD)
print(mystery.isUndefined)         // true
print(mystery.text)                // ".long 0xbadbad"
```

The same `(word, address, features)` always produces the same value, on every platform.

## The value you get back

The mnemonic is a first-class ``Mnemonic`` with a canonical lowercase name, operands are a zero-based collection, and every semantic classification is a typed field.

```swift
let add = decode(0x91040108)                  // add x8, x8, #256
print(add.mnemonic.name)                      // "add"
print(add.operands.count)                     // 3
print(add.semanticReads.map(\.name))          // ["x8"]
print(add.semanticWrites.map(\.name))         // ["x8"]
print(add.category)                           // dataProcessingImmediate
```

Aliases resolve the way official tooling prefers them. `0xAA0103E2` is architecturally `orr x2, xzr, x1`; iris renders the preferred alias and keeps the semantics exact.

```swift
let move = decode(0xAA0103E2)
print(move.text)                              // "mov x2, x1"
print(move.semanticReads.map(\.name))         // ["x1"]
```

## Addresses

PC-relative instructions resolve against the `at:` address, modulo 2^64. Targets are API (see <doc:TheSemanticLayer>); the text keeps the relative `#offset` form oracle tooling prints.

```swift
let branch = decode(0x97FFFFDF, at: 0x1000003AC)      // bl #-132
print(branch.text)                                    // "bl #-132"
print(String(branch.branchTarget!, radix: 16))        // "100000328"
```

## Features

``Features/arm64e`` adds the LDRAA/LDRAB load tier, whose words are unallocated on plain ARM64. ``Features/base`` is the named empty set `decode` uses by default. PAC encodings that exist on the base ISA (`paciasp`, `retaa`, `braa`) decode regardless.

```swift
let word: UInt32 = 0xF8200400                      // ldraa x0, [x0]
print(decode(word, features: .base).isUndefined)   // true
print(decode(word, features: .arm64e).text)        // "ldraa x0, [x0]"
```

## Beyond one word

``InstructionStream`` is the bulk tier: packed storage, constant-time address lookup, stream-level diagnostics. <doc:DisassemblingWithYourOwnLoader> covers it in full.

```swift
let bytes: [UInt8] = [0xFD, 0x7B, 0xBF, 0xA9,      // stp x29, x30, [sp, #-16]!
                      0xFD, 0x03, 0x00, 0x91,      // mov x29, sp
                      0xC0, 0x03, 0x5F, 0xD6]      // ret
let stream = InstructionStream(bytes: bytes, at: 0x4000)
for instruction in stream {
    print("\(String(instruction.address, radix: 16)): \(instruction.text)")
}
```

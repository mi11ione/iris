# Decode your first instruction

Three lines from an instruction word to canonical assembly, and a tour of the value you get back.

## Overview

The smallest entry point is the module-scope ``decode(_:at:features:)``: one little-endian 4-byte word in, one ``Instruction`` out, no ceremony.

```swift
import Iris

let instruction = decode(0xD503201F)
print(instruction.text)            // "nop"
```

Decode is **total**. Every possible 32-bit word produces a well-formed ``Instruction``; unknown or unallocated encodings never crash and never produce a plausible-looking wrong answer. They return a record whose ``Instruction/isUndefined`` is `true`, with the raw word preserved in ``Instruction/encoding`` and a text rendering of `.long 0x<hex>`.

```swift
let mystery = decode(0x00BADBAD)
print(mystery.isUndefined)         // true
print(mystery.text)                // ".long 0xbadbad"
```

It is also **deterministic and pure**: the same `(word, address, features)` always produces the same value, on every platform.

## The value you get back

An ``Instruction`` carries the full decode result. The mnemonic is a first-class ``Mnemonic`` with a canonical lowercase name, operands are a zero-based collection, and every semantic classification is a typed field.

```swift
let add = decode(0x91040108)                  // add x8, x8, #256
print(add.mnemonic.name)                      // "add"
print(add.operands.count)                     // 3
print(add.semanticReads.map(\.name))          // ["x8"]
print(add.semanticWrites.map(\.name))         // ["x8"]
print(add.category)                           // dataProcessingImmediate
```

Aliases resolve the way official tooling prefers them. The word `0xAA0103E2` is architecturally `orr x2, xzr, x1`; iris renders the preferred alias while keeping the semantics exact.

```swift
let move = decode(0xAA0103E2)
print(move.text)                              // "mov x2, x1"
print(move.semanticReads.map(\.name))         // ["x1"]
```

## Addresses

PC-relative instructions resolve against the `at:` address, modulo 2^64. Branch targets and address-formation results are API (see <doc:TheSemanticLayer>), while the textual rendering keeps the relative `#offset` form that oracle tooling prints.

```swift
let branch = decode(0x97FFFFDF, at: 0x1000003AC)   // bl #-132
print(branch.text)                                 // "bl #-132"
print(branch.branchTarget.map { String($0, radix: 16) } ?? "-")
// "100000328" (the absolute target, resolved for you)
```

## Features

Most of the instruction set needs no opt-in. NEON and floating point, crypto, MTE, the atomics tiers, Apple's AMX coprocessor, and the scalable tiers all decode by default.

```swift
print(decode(0x04220020).text)   // "add z0.b, z1.b, z2.b" (SVE)
print(decode(0x8080FC00).text)   // "fmopa za0.s, p7/m, p7/m, z0.s, z0.s" (SME)
```

``Features`` is for the one case that needs a target decision — an encoding space meaning different things on different targets. ``Features/arm64e`` adds the LDRAA/LDRAB load tier, whose words are unallocated on plain ARM64; ``Features/base`` is the named spelling of the empty set that `decode` uses by default.

```swift
let word: UInt32 = 0xF8200400                      // ldraa x0, [x0]
print(decode(word, features: .base).isUndefined)   // true  (plain ARM64)
print(decode(word, features: .arm64e).text)        // "ldraa x0, [x0]"
```

PAC encodings that exist on the base ISA (hint-space `paciasp`, `retaa`, `braa`) decode regardless of the flag.

## Beyond one word

For buffers, construct an ``InstructionStream`` — the bulk tier, with packed storage, constant-time address lookup, and stream-level diagnostics.

```swift
let bytes: [UInt8] = [0xFD, 0x7B, 0xBF, 0xA9,      // stp x29, x30, [sp, #-16]!
                      0xFD, 0x03, 0x00, 0x91,      // mov x29, sp
                      0xC0, 0x03, 0x5F, 0xD6]      // ret
let stream = InstructionStream(bytes: bytes, at: 0x4000)
for instruction in stream {
    print("\(String(instruction.address, radix: 16)): \(instruction.text)")
}
```

<doc:DisassemblingWithYourOwnLoader> covers the stream tier in full.

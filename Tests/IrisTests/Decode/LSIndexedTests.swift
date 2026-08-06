// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the post- and pre-indexed classes.
@Suite("L/S post/pre-indexed decode")
struct LSIndexedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func postIndexedLoadWritesBaseAndDestination() {
        let d = decode(0xB840_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
        #expect(d.memoryAccess == .load)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func postIndexedDisplacementIsUnscaled() {
        let d = decode(0xB840_1400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1, writeback: .postIndex)))
    }

    @Test func preIndexedLoadDoublewordForm() {
        let d = decode(0xF840_0C00)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
    }

    @Test func preIndexedDisplacement() {
        let d = decode(0xF840_1C00)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1, writeback: .preIndex)))
    }

    @Test func negativeImm9SignExtendsForPostIndex() {
        let d = decode(0xF850_0400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: -256, writeback: .postIndex)))
    }

    @Test func negativeImm9SignExtendsForPreIndex() {
        let d = decode(0xB850_0C00)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: -256, writeback: .preIndex)))
    }

    @Test func postIndexedStoreWritesBaseOnly() {
        let d = decode(0xB800_0400)
        #expect(d.mnemonic == .str)
        #expect(d.memoryAccess == .store)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func reservedIndexedEncodingReturnsUndefined() {
        #expect(decode(0xF880_0400).mnemonic == .undefined)
    }

    @Test func distinctRegistersProveTheReadWriteRoles() {
        let d = decode(0xB840_4441)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(2)), displacement: 4, writeback: .postIndex)),
        ])
        #expect(d.semanticReads.mask == UInt64(1) << 2)
        #expect(d.semanticWrites.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
    }
}

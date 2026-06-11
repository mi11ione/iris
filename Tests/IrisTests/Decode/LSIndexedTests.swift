// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the post- and pre-indexed register classes. Both share
/// the LDUR shell; bits[11:10] select the writeback mode. Checks the
/// writeback marker and the base-register writeback in the
/// semantic-writes mask.
@Suite("L/S post/pre-indexed decode")
struct LSIndexedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func postIndexedLoadWritesBaseAndDestination() {
        // 0xb8400400 = ldr w0, [x0], #0.
        let d = decode(0xB840_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .postIndex)))
        #expect(d.memoryAccess == .load)
        // Post-index load writes Rt + the writeback base register.
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func postIndexedDisplacementIsUnscaled() {
        // 0xb8401400 = ldr w0, [x0], #1.
        let d = decode(0xB840_1400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1, writeback: .postIndex)))
    }

    @Test func preIndexedLoadDoublewordForm() {
        // 0xf8400c00 = ldr x0, [x0, #0]!.
        let d = decode(0xF840_0C00)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
    }

    @Test func preIndexedDisplacement() {
        // 0xf8401c00 = ldr x0, [x0, #1]!.
        let d = decode(0xF840_1C00)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1, writeback: .preIndex)))
    }

    @Test func negativeImm9SignExtendsForPostIndex() {
        // 0xf8500400 = ldr x0, [x0], #-256.
        let d = decode(0xF850_0400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: -256, writeback: .postIndex)))
    }

    @Test func negativeImm9SignExtendsForPreIndex() {
        // 0xb8500c00 = ldr w0, [x0, #-256]!.
        let d = decode(0xB850_0C00)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: -256, writeback: .preIndex)))
    }

    @Test func postIndexedStoreWritesBaseOnly() {
        // 0xb8000400 = str w0, [x0], #0 — a store with writeback.
        let d = decode(0xB800_0400)
        #expect(d.mnemonic == .str)
        #expect(d.memoryAccess == .store)
        // Store reads Rt + Rn; writes only the writeback base.
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func reservedIndexedEncodingReturnsUndefined() {
        // 0xf8800400 — size=11, opc=10 has no indexed form (PRFM has none).
        #expect(decode(0xF880_0400).mnemonic == .undefined)
    }

    @Test func distinctRegistersProveTheReadWriteRoles() {
        // 0xb8404441 = ldr w1, [x2], #4 — distinct Rt / Rn so the base,
        // destination and writeback-base masks cannot collapse onto the
        // same bit (an all-register-0 fixture passes even if an operand
        // is dropped).
        let d = decode(0xB840_4441)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(2)), displacement: 4, writeback: .postIndex)),
        ])
        // Load reads the base x2; writes Rt w1 plus the writeback base x2.
        #expect(d.semanticReads.mask == UInt64(1) << 2)
        #expect(d.semanticWrites.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
    }
}

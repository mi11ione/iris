// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the ARM64E LDRAA / LDRAB class.
@Suite("L/S LDRAA/LDRAB decode")
struct LSLDRATests {
    private func decodeE(_ e: UInt32) -> Instruction {
        decode(e, at: 0, features: .arm64e)
    }

    @Test func ldraaSignedOffsetForm() {
        let d = decodeE(0xF820_0400)
        #expect(d.mnemonic == .ldraa)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [])
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)))))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func imm10IsScaledByEight() {
        let d = decodeE(0xF820_1400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 8)))
    }

    @Test func writebackBitSelectsPreIndex() {
        let d = decodeE(0xF820_0C00)
        #expect(d.mnemonic == .ldraa)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func mBitSelectsTheLdrabKey() {
        let d = decodeE(0xF8A0_0400)
        #expect(d.mnemonic == .ldrab)
        #expect(d.memoryAccess == .load)
    }

    @Test func decodingRequiresArm64EContext() {
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func nonDoublewordSizeReturnsUndefined() {
        let d = decodeE(0x7820_0400)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheReadWriteRoles() {
        let d = decodeE(0xF820_0441)
        #expect(d.mnemonic == .ldraa)
        #expect(Array(d.operands) == [
            .register(.x(1)),
            .memory(MemoryOperand(base: .register(.x(2)))),
        ])
        #expect(d.semanticReads.mask == UInt64(1) << 2)
        #expect(d.semanticWrites.mask == UInt64(1) << 1)
    }

    @Test func distinctRegistersWithWritebackAddTheBase() {
        let d = decodeE(0xF820_1C41)
        #expect(d.mnemonic == .ldraa)
        #expect(Array(d.operands) == [
            .register(.x(1)),
            .memory(MemoryOperand(base: .register(.x(2)), displacement: 8, writeback: .preIndex)),
        ])
        #expect(d.semanticReads.mask == UInt64(1) << 2)
        #expect(d.semanticWrites.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
    }
}

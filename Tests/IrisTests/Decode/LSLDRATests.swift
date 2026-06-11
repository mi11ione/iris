// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L15 ARM64E PAC-authenticated load class —
/// LDRAA / LDRAB. The `M` bit picks the key, `W` picks pre-index
/// writeback, and imm10 is scaled by 8. The class only decodes when
/// `Features` carries `.pointerAuthentication` (the `.arm64e` preset).
@Suite("L/S LDRAA/LDRAB decode")
struct LSLDRATests {
    private func decodeE(_ e: UInt32) -> Instruction {
        decode(e, at: 0, features: .arm64e)
    }

    @Test func ldraaSignedOffsetForm() {
        // 0xf8200400 = ldraa x0, [x0] — M=0, W=0, no writeback.
        let d = decodeE(0xF820_0400)
        #expect(d.mnemonic == .ldraa)
        #expect(d.memoryAccess == .load)
        #expect(d.memoryOrdering == [])
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)))))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func imm10IsScaledByEight() {
        // 0xf8201400 = ldraa x0, [x0, #8] — imm10=1, ×8 → +8.
        let d = decodeE(0xF820_1400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 8)))
    }

    @Test func writebackBitSelectsPreIndex() {
        // 0xf8200c00 = ldraa x0, [x0, #0]! — W=1 → pre-index writeback.
        let d = decodeE(0xF820_0C00)
        #expect(d.mnemonic == .ldraa)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), writeback: .preIndex)))
        // Pre-index adds the base register to the write set.
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func mBitSelectsTheLdrabKey() {
        // 0xf8a00400 = ldrab x0, [x0] — M=1 selects the DB key.
        let d = decodeE(0xF8A0_0400)
        #expect(d.mnemonic == .ldrab)
        #expect(d.memoryAccess == .load)
    }

    @Test func decodingRequiresArm64EContext() {
        // The LDRAA encoding is unallocated on plain ARM64.
        let d = decode(0xF820_0400, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func nonDoublewordSizeReturnsUndefined() {
        // 0x78200400 — size=01; LDRAA/LDRAB are 64-bit doubleword only.
        let d = decodeE(0x7820_0400)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheReadWriteRoles() {
        // 0xf8200441 = ldraa x1, [x2] — distinct Rt / Rn so the read
        // (base x2) and the write (destination x1) are separate bits.
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
        // 0xf8201c41 = ldraa x1, [x2, #8]! — W=1 pre-index writeback adds
        // the base x2 to the write set alongside the destination x1.
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

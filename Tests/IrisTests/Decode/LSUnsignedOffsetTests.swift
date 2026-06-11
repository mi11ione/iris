// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L12 unsigned-offset class — the scaled
/// imm12 forms of LDR / STR and friends. The imm12 field is unsigned and
/// scaled by `1 << size`; checks mnemonic, the scaled displacement, and
/// the PRFM operand-slot reuse.
@Suite("L/S unsigned-offset decode")
struct LSUnsignedOffsetTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func strWordZeroOffset() {
        // 0xb9000000 = str w0, [x0].
        let d = decode(0xB900_0000)
        #expect(d.mnemonic == .str)
        #expect(d.memoryAccess == .store)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)))))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func wordOffsetScalesImm12ByFour() {
        // 0xb9000400 = str w0, [x0, #4] — imm12=1, size=10 → ×4.
        let d = decode(0xB900_0400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 4)))
    }

    @Test func doublewordOffsetScalesImm12ByEight() {
        // 0xf9400400 = ldr x0, [x0, #8] — imm12=1, size=11 → ×8.
        let d = decode(0xF940_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 8)))
    }

    @Test func ldrDoublewordZeroOffset() {
        // 0xf9400000 = ldr x0, [x0].
        let d = decode(0xF940_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldrWordOffset() {
        // 0xb9400400 = ldr w0, [x0, #4].
        let d = decode(0xB940_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.first == .register(.w(0)))
    }

    @Test func prfmUnsignedOffsetCarriesPrefetchOperand() {
        // 0xf9800000 = prfm pldl1keep, [x0].
        let d = decode(0xF980_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.memoryAccess == .prefetch)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        // 0xf9c00000 — size=11, opc=11 has no unsigned-offset instruction.
        #expect(decode(0xF9C0_0000).mnemonic == .undefined)
    }
}

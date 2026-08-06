// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the scaled imm12 forms.
@Suite("L/S unsigned-offset decode")
struct LSUnsignedOffsetTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func strWordZeroOffset() {
        let d = decode(0xB900_0000)
        #expect(d.mnemonic == .str)
        #expect(d.memoryAccess == .store)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)))))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func wordOffsetScalesImm12ByFour() {
        let d = decode(0xB900_0400)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 4)))
    }

    @Test func doublewordOffsetScalesImm12ByEight() {
        let d = decode(0xF940_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 8)))
    }

    @Test func ldrDoublewordZeroOffset() {
        let d = decode(0xF940_0000)
        #expect(d.mnemonic == .ldr)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldrWordOffset() {
        let d = decode(0xB940_0400)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands.first == .register(.w(0)))
    }

    @Test func prfmUnsignedOffsetCarriesPrefetchOperand() {
        let d = decode(0xF980_0000)
        #expect(d.mnemonic == .prfm)
        #expect(d.memoryAccess == .prefetch)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        #expect(decode(0xF9C0_0000).mnemonic == .undefined)
    }
}

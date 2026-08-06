// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the unscaled-immediate class including PRFUM.
@Suite("L/S unscaled-immediate decode")
struct LSUnscaledTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func sturWordForm() {
        let d = decode(0xB800_0000)
        #expect(d.mnemonic == .stur)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func ldurDoublewordForm() {
        let d = decode(0xF840_0000)
        #expect(d.mnemonic == .ldur)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func sturbAndLdurbByteForms() {
        #expect(decode(0x3800_0000).mnemonic == .sturb)
        #expect(decode(0x3840_0000).mnemonic == .ldurb)
    }

    @Test func sturhHalfwordForm() {
        #expect(decode(0x7800_0000).mnemonic == .sturh)
    }

    @Test func ldursbSignExtendsToXt() {
        let d = decode(0x3880_0000)
        #expect(d.mnemonic == .ldursb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func imm9IsUnscaledAndNotShifted() {
        let d = decode(0x3800_1000)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), displacement: 1)))
    }

    @Test func prfumCarriesPrefetchOperand() {
        let d = decode(0xF880_0000)
        #expect(d.mnemonic == .prfum)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.memoryAccess == .prefetch)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedSizeOpcReturnsUndefined() {
        #expect(decode(0xB8C0_0000).mnemonic == .undefined)
    }
}

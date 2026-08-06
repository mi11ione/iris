// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the unprivileged LDTR / STTR class.
@Suite("L/S unprivileged (LDTR) decode")
struct LSUnprivilegedTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func sttrWordStore() {
        let d = decode(0xB800_0800)
        #expect(d.mnemonic == .sttr)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .store)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func ldtrDoublewordLoad() {
        let d = decode(0xF840_0800)
        #expect(d.mnemonic == .ldtr)
        #expect(d.memoryAccess == .load)
        #expect(d.operands.first == .register(.x(0)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldtrbAndSttrbByteForms() {
        #expect(decode(0x3840_0800).mnemonic == .ldtrb)
        #expect(decode(0x3800_0800).mnemonic == .sttrb)
    }

    @Test func ldtrhHalfwordForm() {
        #expect(decode(0x7840_0800).mnemonic == .ldtrh)
    }

    @Test func ldtrsbSignExtendsToXt() {
        let d = decode(0x3880_0800)
        #expect(d.mnemonic == .ldtrsb)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func ldtrshWidthFollowsOpcNotSize() {
        let xtForm = decode(0x7880_0800)
        #expect(xtForm.mnemonic == .ldtrsh)
        #expect(xtForm.operands.first == .register(.x(0)))
        let wtForm = decode(0x78C0_0800)
        #expect(wtForm.mnemonic == .ldtrsh)
        #expect(wtForm.operands.first == .register(.w(0)))
    }

    @Test func ldtrswForm() {
        let d = decode(0xB880_0800)
        #expect(d.mnemonic == .ldtrsw)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func reservedUnprivilegedEncodingReturnsUndefined() {
        #expect(decode(0xB8C0_0800).mnemonic == .undefined)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `[Rn, Rm, ext]` addressing.
@Suite("L/S register-offset decode")
struct LSRegisterOffsetTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func uxtwExtendWithoutShiftUsesTheSentinel() {
        let d = decode(0x3820_4800)
        #expect(d.mnemonic == .strb)
        #expect(d.memoryAccess == .store)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .uxtw, shift: 0xFF)))
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites == .empty)
    }

    @Test func lslOptionWithSZeroCollapsesToBareRegister() {
        let d = decode(0x3820_6800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0))))
    }

    @Test func lslOptionWithSOneKeepsLslKeyword() {
        let d = decode(0x3820_7800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .lsl)))
    }

    @Test func sxtwUsesA32BitIndexRegister() {
        let d = decode(0x3820_C800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .sxtw, shift: 0xFF)))
    }

    @Test func sxtxUsesA64BitIndexAndDisplaysAmount() {
        let d = decode(0x3820_F800)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .sxtx)))
    }

    @Test func shiftAmountTracksTheSizeFieldWhenSIsSet() {
        let d = decode(0xF820_7800)
        #expect(d.mnemonic == .str)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .x(0), extend: .lsl, shift: 3)))
    }

    @Test func wordLoadShiftAmountIsTwo() {
        let d = decode(0xB860_5800)
        #expect(d.mnemonic == .ldr)
        #expect(d.operands[1] == .memory(MemoryOperand(base: .register(.x(0)), index: .w(0), extend: .uxtw, shift: 2)))
    }

    @Test func prfmRegisterOffsetCarriesPrefetchOperand() {
        let d = decode(0xF8A0_4800)
        #expect(d.mnemonic == .prfm)
        #expect(d.memoryAccess == .prefetch)
        #expect(d.operands.first == .prefetchOperation(PrefetchOperation(rawValue: 0)))
        #expect(d.semanticWrites == .empty)
    }

    @Test func reservedExtendOptionReturnsUndefined() {
        let d = decode(0x3820_0800)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveBaseIndexAndDestination() {
        let d = decode(0xB863_5841)
        #expect(d.mnemonic == .ldr)
        #expect(Array(d.operands) == [
            .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(2)), index: .w(3), extend: .uxtw, shift: 2)),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == UInt64(1) << 1)
    }
}

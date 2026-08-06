// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the compare-and-swap class.
@Suite("L/S compare-and-swap decode")
struct LSCompareAndSwapTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func casWordPlainOrdering() {
        let d = decode(0x88A0_7C00)
        #expect(d.mnemonic == .cas)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func casDoublewordForm() {
        let d = decode(0xC8A0_7C00)
        #expect(d.mnemonic == .cas)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func casByteForm() {
        #expect(decode(0x08A0_7C00).mnemonic == .casb)
    }

    @Test func casAcquireForm() {
        let d = decode(0x88E0_7C00)
        #expect(d.mnemonic == .casa)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func casReleaseForm() {
        let d = decode(0x88A0_FC00)
        #expect(d.mnemonic == .casl)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func casAcquireReleaseForm() {
        let d = decode(0x88E0_FC00)
        #expect(d.mnemonic == .casal)
        #expect(d.memoryOrdering == [.acquire, .release])
    }

    @Test func casHalfwordAcquireForm() {
        let d = decode(0x48E0_7C00)
        #expect(d.mnemonic == .casah)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func reservedBits14To10ReturnsUndefined() {
        let d = decode(0x88A0_7800)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func caspPairPlainOrdering() {
        let d = decode(0x0820_7C00)
        #expect(d.mnemonic == .casp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(1)),
            .register(.w(0)), .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        #expect(d.semanticReads.mask == (UInt64(1) << 0) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0) | (UInt64(1) << 1))
    }

    @Test func caspReleaseAndAcquireReleaseForms() {
        #expect(decode(0x0820_FC00).mnemonic == .caspl)
        #expect(decode(0x0860_FC00).memoryOrdering == [.acquire, .release])
    }

    @Test func caspOddRegisterReturnsUndefined() {
        let d = decode(0x0821_7C00)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheCasReadWriteRoles() {
        let d = decode(0x88A1_7C62)
        #expect(d.mnemonic == .cas)
        #expect(Array(d.operands) == [
            .register(.w(1)), .register(.w(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == UInt64(1) << 1)
    }
}

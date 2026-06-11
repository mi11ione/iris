// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L5 compare-and-swap class — CAS / CASA /
/// CASL / CASAL plus the byte/halfword forms and the CASP register-pair
/// forms. Checks the (size, A, R) → mnemonic map, atomic classification,
/// the reserved bits[14:10] guard, and the CASP even-register constraint.
@Suite("L/S compare-and-swap decode")
struct LSCompareAndSwapTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func casWordPlainOrdering() {
        // 0x88a07c00 = cas w0, w0, [x0].
        let d = decode(0x88A0_7C00)
        #expect(d.mnemonic == .cas)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        // CAS reads Rs + Rt + Rn; writes Rs (the old value loaded back).
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func casDoublewordForm() {
        // 0xc8a07c00 = cas x0, x0, [x0] — size=11 selects the Xt width.
        let d = decode(0xC8A0_7C00)
        #expect(d.mnemonic == .cas)
        #expect(d.operands.first == .register(.x(0)))
    }

    @Test func casByteForm() {
        // 0x08a07c00 = casb w0, w0, [x0].
        #expect(decode(0x08A0_7C00).mnemonic == .casb)
    }

    @Test func casAcquireForm() {
        // 0x88e07c00 = casa w0, w0, [x0] — A=1.
        let d = decode(0x88E0_7C00)
        #expect(d.mnemonic == .casa)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func casReleaseForm() {
        // 0x88a0fc00 = casl w0, w0, [x0] — R=1.
        let d = decode(0x88A0_FC00)
        #expect(d.mnemonic == .casl)
        #expect(d.memoryOrdering == [.release])
    }

    @Test func casAcquireReleaseForm() {
        // 0x88e0fc00 = casal w0, w0, [x0] — A=1, R=1.
        let d = decode(0x88E0_FC00)
        #expect(d.mnemonic == .casal)
        #expect(d.memoryOrdering == [.acquire, .release])
    }

    @Test func casHalfwordAcquireForm() {
        // 0x48e07c00 = casah w0, w0, [x0].
        let d = decode(0x48E0_7C00)
        #expect(d.mnemonic == .casah)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func reservedBits14To10ReturnsUndefined() {
        // CAS requires bits[14:10] == 11111; 0x88a07800 has them at 11110.
        let d = decode(0x88A0_7800)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func caspPairPlainOrdering() {
        // 0x08207c00 = casp w0, w1, w0, w1, [x0].
        let d = decode(0x0820_7C00)
        #expect(d.mnemonic == .casp)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(1)),
            .register(.w(0)), .register(.w(1)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        // CASP reads Rs/Rs+1 + Rt/Rt+1 + Rn; writes Rs/Rs+1.
        #expect(d.semanticReads.mask == (UInt64(1) << 0) | (UInt64(1) << 1))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0) | (UInt64(1) << 1))
    }

    @Test func caspReleaseAndAcquireReleaseForms() {
        // 0x0820fc00 = caspl; 0x0860fc00 = caspal.
        #expect(decode(0x0820_FC00).mnemonic == .caspl)
        #expect(decode(0x0860_FC00).memoryOrdering == [.acquire, .release])
    }

    @Test func caspOddRegisterReturnsUndefined() {
        // 0x08217c00 — Rs is odd (bit16=1); CASP constrains Rs/Rt even.
        let d = decode(0x0821_7C00)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func distinctRegistersProveTheCasReadWriteRoles() {
        // 0x88a17c62 = cas w1, w2, [x3] — distinct Rs / Rt / Rn. CAS reads
        // all three (Rs expected, Rt replacement, Rn base) and writes Rs
        // (the old memory value loaded back); distinct registers prove the
        // write targets Rs and not, say, Rt.
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

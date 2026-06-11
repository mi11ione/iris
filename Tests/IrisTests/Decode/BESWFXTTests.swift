// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates WFET / WFIT decode item 30: op2 selects
/// (000 → WFET, 001 → WFIT, other → UNDEFINED), Rt at bits 4:0 carries
/// the timeout register, CRm must be 0, bits 18:16 must be 011.
@Suite("BES / WFET / WFIT decode (FEAT_WFxT)")
struct BESWFXTTests {
    @Test func wfetX0() {
        // 0xD5031000 = WFET X0
        let d = decode(0xD503_1000, at: 0)
        #expect(d.mnemonic == .wfet)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func wfitX1() {
        // 0xD5031021 = WFIT X1 (op2=001)
        let d = decode(0xD503_1021, at: 0)
        #expect(d.mnemonic == .wfit)
        #expect(d.operands[0] == .register(.x(1)))
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func wfetXzr() {
        // Rt = 31 → XZR
        let d = decode(0xD503_101F, at: 0)
        #expect(d.mnemonic == .wfet)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func wfetVariousRt() {
        for rt: UInt8 in [0, 1, 16, 30, 31] {
            let enc = UInt32(0xD503_1000) | UInt32(rt)
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .wfet)
        }
    }

    @Test func reservedOp2IsMsr() {
        // op2 = 010 is not WFET/WFIT; it's an op0 == 0 MSR
        // (the oracle renders `msr S0_3_C1_C0_2, x0`).
        let d = decode(0xD503_1040, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func nonZeroCRmIsMsr() {
        // CRm != 0 is not WFET/WFIT; an op0 == 0 MSR.
        let d = decode(0xD503_1100, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func wrongBits18To16IsMsr() {
        // bits 18:16 != 011 is not WFET/WFIT; an op0 == 0 MSR
        // (the oracle renders `msr S0_0_C1_C0_0, x0`).
        let d = decode(0xD500_1000, at: 0)
        #expect(d.mnemonic == .msr)
    }
}

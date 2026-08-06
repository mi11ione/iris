// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates WFET / WFIT.
@Suite("BES / WFET / WFIT decode (FEAT_WFxT)")
struct BESWFXTTests {
    @Test func wfetX0() {
        let d = decode(0xD503_1000, at: 0)
        #expect(d.mnemonic == .wfet)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func wfitX1() {
        let d = decode(0xD503_1021, at: 0)
        #expect(d.mnemonic == .wfit)
        #expect(d.operands[0] == .register(.x(1)))
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func wfetXzr() {
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
        let d = decode(0xD503_1040, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func nonZeroCRmIsMsr() {
        let d = decode(0xD503_1100, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func wrongBits18To16IsMsr() {
        let d = decode(0xD500_1000, at: 0)
        #expect(d.mnemonic == .msr)
    }
}

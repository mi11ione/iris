// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the DPR family's dispatch behavior through the public
/// surface: op0 routing into the family and the
/// (bit 28, bit 24, bits 23:21) sub-dispatch to per-class decoders.
@Suite("DPR / DataProcessingRegisterDecoder dispatch")
struct DPRDispatcherTests {
    @Test func op0_0x5_bit24_0_routesToLogicalShifted() {
        // AND x0, x1, x2 — op0=0x5, bit 24=0.
        let d = decode(0x8A02_0020, at: 0)
        #expect(d.mnemonic == .and)
    }

    @Test func op0_0x5_bit24_1_bit21_0_routesToAddSubShifted() {
        // ADD x0, x1, x2 — op0=0x5, bit 24=1, bit 21=0.
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func op0_0x5_bit24_1_bit21_1_routesToAddSubExtended() {
        // ADD x0, x1, x2, UXTX — op0=0x5, bit 24=1, bit 21=1.
        let d = decode(0x8B22_6020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.last == .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0))
    }

    @Test func op0_0xD_bit24_0_bits23_21_000_routesToAddSubCarry() {
        // ADC x0, x1, x2.
        let d = decode(0x9A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
    }

    @Test func op0_0xD_bit24_0_bits23_21_010_routesToCondCompare() {
        // CCMP x1, x2, #0, EQ (register form).
        let d = decode(0xFA42_0040, at: 0)
        #expect(d.mnemonic == .ccmp)
    }

    @Test func op0_0xD_bit24_0_bits23_21_100_routesToCondSelect() {
        // CSEL x0, x1, x2, EQ.
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
    }

    @Test func op0_0xD_bit24_0_bits23_21_110_routesToDataProc2or1Source() {
        // RBIT x0, x1 (1-source path).
        let d = decode(0xDAC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
    }

    @Test func op0_0xD_bit24_1_routesToMulAccum() {
        // MADD x0, x1, x2, x3.
        let d = decode(0x9B03_0C20, at: 0)
        #expect(d.mnemonic == .madd)
    }

    @Test func reservedSubTreeBits23_21_001_returnsUndefined() {
        // op0=0xD, bit 24=0, bits 23:21=001 — reserved.
        // bit 21=1 placed via the otherwise valid ADC base.
        let encoding: UInt32 = 0x9A22_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func reservedSubTreeBits23_21_011_returnsUndefined() {
        // op0=0xD, bit 24=0, bits 23:21=011 (bits 22+21 set) — reserved.
        let encoding: UInt32 = 0x9A62_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSubTreeBits23_21_101_returnsUndefined() {
        // op0=0xD, bit 24=0, bits 23:21=101 — reserved.
        let encoding: UInt32 = 0x9AA2_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSubTreeBits23_21_111_returnsUndefined() {
        // op0=0xD, bit 24=0, bits 23:21=111 — reserved.
        let encoding: UInt32 = 0x9AE2_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedTierOp0DecodesUndefined() {
        // The architecturally reserved op0 tier {1, 2, 3} has no family;
        // routing for every other op0 is pinned in DispatchRoutingTests.
        for op0: UInt32 in 1 ... 3 {
            let encoding = op0 << 25
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "op0=\(op0) must return UNDEFINED")
            #expect(d.category == .undefined, "op0=\(op0) must have category UNDEFINED")
            #expect(d.encoding == encoding, "encoding must be preserved")
        }
    }

    @Test func contextArgumentIsIgnoredButPlumbed() {
        // DPR doesn't consult the ARM64E gate; pass ARM64E and confirm unchanged.
        let d = decode(0x8B02_0020, at: 0, features: .arm64e)
        #expect(d.mnemonic == .add)
    }

    @Test func addressAndEncodingPropagateToDraft() {
        let d = decode(0x8B02_0020, at: 0xABCD)
        #expect(d.encoding == 0x8B02_0020)
        #expect(d.address == 0xABCD)
    }
}

/// Verifies the standard family composition routes the DPR op0
/// partition {0x5, 0xD} to the DPR family, asserted through public
/// category attribution.
@Suite("DPR / standard family composition")
struct DPRStandardDecoderSetTests {
    @Test func op5RoutesToDPRDecoder() {
        // op0=0x5 witness: AND x0, x1, x2.
        #expect(decode(0x8A02_0020).category == .dataProcessingRegister)
    }

    @Test func opDRoutesToDPRDecoder() {
        // op0=0xD witness: MADD.
        #expect(decode(0x9B00_7C20).category == .dataProcessingRegister)
    }

    @Test func machineCodeDispatchRoutesToDPR() {
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.mnemonic == .add)
    }
}

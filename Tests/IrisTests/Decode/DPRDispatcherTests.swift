// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates DPR dispatch through the public surface.
@Suite("DPR / DataProcessingRegisterDecoder dispatch")
struct DPRDispatcherTests {
    @Test func op0_0x5_bit24_0_routesToLogicalShifted() {
        let d = decode(0x8A02_0020, at: 0)
        #expect(d.mnemonic == .and)
    }

    @Test func op0_0x5_bit24_1_bit21_0_routesToAddSubShifted() {
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func op0_0x5_bit24_1_bit21_1_routesToAddSubExtended() {
        let d = decode(0x8B22_6020, at: 0)
        #expect(d.mnemonic == .add)
        #expect(d.operands.last == .extendedRegister(reg: .x(2), extend: .uxtx, shift: 0))
    }

    @Test func op0_0xD_bit24_0_bits23_21_000_routesToAddSubCarry() {
        let d = decode(0x9A02_0020, at: 0)
        #expect(d.mnemonic == .adc)
    }

    @Test func op0_0xD_bit24_0_bits23_21_010_routesToCondCompare() {
        let d = decode(0xFA42_0040, at: 0)
        #expect(d.mnemonic == .ccmp)
    }

    @Test func op0_0xD_bit24_0_bits23_21_100_routesToCondSelect() {
        let d = decode(0x9A82_0020, at: 0)
        #expect(d.mnemonic == .csel)
    }

    @Test func op0_0xD_bit24_0_bits23_21_110_routesToDataProc2or1Source() {
        let d = decode(0xDAC0_0020, at: 0)
        #expect(d.mnemonic == .rbit)
    }

    @Test func op0_0xD_bit24_1_routesToMulAccum() {
        let d = decode(0x9B03_0C20, at: 0)
        #expect(d.mnemonic == .madd)
    }

    @Test func reservedSubTreeBits23_21_001_returnsUndefined() {
        let encoding: UInt32 = 0x9A22_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
    }

    @Test func reservedSubTreeBits23_21_011_returnsUndefined() {
        let encoding: UInt32 = 0x9A62_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSubTreeBits23_21_101_returnsUndefined() {
        let encoding: UInt32 = 0x9AA2_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSubTreeBits23_21_111_returnsUndefined() {
        let encoding: UInt32 = 0x9AE2_0020
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedTierOp0DecodesUndefined() {
        for op0: UInt32 in [1, 3] {
            let encoding = op0 << 25
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .undefined, "op0=\(op0) must return UNDEFINED")
            #expect(d.category == .undefined, "op0=\(op0) must have category UNDEFINED")
            #expect(d.encoding == encoding, "encoding must be preserved")
        }
    }

    @Test func contextArgumentIsIgnoredButPlumbed() {
        let d = decode(0x8B02_0020, at: 0, features: .arm64e)
        #expect(d.mnemonic == .add)
    }

    @Test func addressAndEncodingPropagateToDraft() {
        let d = decode(0x8B02_0020, at: 0xABCD)
        #expect(d.encoding == 0x8B02_0020)
        #expect(d.address == 0xABCD)
    }
}

/// Verifies the standard composition routes op0 {0x5, 0xD} to DPR, asserted
/// through public category attribution.
@Suite("DPR / standard family composition")
struct DPRStandardDecoderSetTests {
    @Test func op5RoutesToDPRDecoder() {
        #expect(decode(0x8A02_0020).category == .dataProcessingRegister)
    }

    @Test func opDRoutesToDPRDecoder() {
        #expect(decode(0x9B00_7C20).category == .dataProcessingRegister)
    }

    @Test func machineCodeDispatchRoutesToDPR() {
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.mnemonic == .add)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the DPI family's dispatch behavior through the public
/// surface: op0 routing into the family and the op1 sub-dispatch to
/// per-class decoders. Hits every op1 case.
@Suite("DPI / DataProcessingImmediateDecoder dispatch")
struct DPIDispatcherTests {
    @Test func op1_000_routesToPCRelADR() {
        // op0=0x8, op1=000 → ADR
        let d = decode(0x1000_0000, at: 0)
        #expect(d.mnemonic == .adr)
    }

    @Test func op1_001_routesToPCRel_immhiBit0Set() {
        // op0=0x8, op1=001 (bit 23=1, which is immhi[0]) → still PC-rel
        let d = decode(0x1080_0000, at: 0)
        #expect(d.mnemonic == .adr)
    }

    @Test func op1_010_routesToAddSubImm() {
        // ADD x0, x1, #0 (op=0, S=0)
        let d = decode(0x9100_0020, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func op1_011_decodesADDG() {
        // op0=0x8 bit 24=1 bit 23=1 → MTE add-with-tags. The MTE decoder
        // owns this row; DPI delegates to MemoryTaggingDecode.decodeDPI.
        // ADDG x0, x0, #0, #0 encoding: 1_0_0_1_00011_0_uimm6_0_0_uimm4_Rn_Rd
        let d = decode(0x9180_0000, at: 0)
        #expect(d.mnemonic == .addg)
        #expect(d.category == .memoryTagging)
    }

    @Test func op1_100_routesToLogicalImm() {
        let d = decode(0x1200_0820, at: 0)
        #expect(d.mnemonic == .and)
    }

    @Test func op1_101_routesToMoveWide() {
        // MOVZ x0, #5121 → MOV alias
        let d = decode(0xD282_8020, at: 0)
        #expect(d.mnemonic == .mov)
    }

    @Test func op1_110_routesToBitfield() {
        // SXTB w0, w1 (SBFM sf=0 immr=0 imms=7)
        let d = decode(0x1300_1C20, at: 0)
        #expect(d.mnemonic == .sxtb)
    }

    @Test func op1_111_routesToExtract() {
        // EXTR x0, x1, x2, #5
        let d = decode(0x93C2_1420, at: 0)
        #expect(d.mnemonic == .extr)
    }

    @Test func featuresArgumentDoesNotPerturbDPIDecode() {
        // DPI has no feature-gated encodings; arm64e must not change it.
        let d = decode(0x9100_0420, at: 0, features: .arm64e)
        #expect(d.mnemonic == .add)
    }

    @Test func addressPropagatesToInstruction() {
        let d = decode(0x9100_0020, at: 0x400)
        #expect(d.address == 0x400)
    }

    @Test func encodingPropagatesToInstruction() {
        let d = decode(0xB100_147F, at: 0)
        #expect(d.encoding == 0xB100_147F)
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
}

/// Validates that the standard family composition routes the DPI op0
/// partition {0x8, 0x9} to the DPI family, asserted through public
/// category attribution.
@Suite("DPI / standard family composition")
struct DPIStandardDecoderSetTests {
    @Test func op8RoutesToDPIDecoder() {
        // op0=0x8 witness: ADR x0, #0.
        #expect(decode(0x1000_0000).category == .dataProcessingImmediate)
    }

    @Test func op9RoutesToDPIDecoder() {
        // op0=0x9 witness: ADD x0, x1, #1.
        #expect(decode(0x9100_0420).category == .dataProcessingImmediate)
    }

    @Test func machineCodeDispatchRoutesToDPI() {
        // ADD x0, x1, #1 via the same dispatch the stream init uses.
        let d = decode(0x9100_0420, at: 0)
        #expect(d.mnemonic == .add)
    }
}

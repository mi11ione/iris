// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the SIMD/FP family's place in the standard composition.
@Suite("SIMD/FP / SIMDAndFPDecoder family registration")
struct SIMDAndFPDecoderRegistrationTests {
    @Test func bothSIMDFPOp0PartitionsAttributeToTheFamily() {
        #expect(decode(0x0E20_1C00).category == .simdAndFP)
        #expect(decode(0x1E20_1000).category == .simdAndFP)
    }
}

/// Validates dispatch into each AdvSIMD / FP scalar sub-class.
@Suite("SIMD/FP / Top-level decode routing")
struct SIMDAndFPDecoderRoutingTests {
    @Test func fpDataProcessing2SourceRoute() {
        let d = decode(0x1E62_2820, at: 0)
        #expect(d.mnemonic == .fadd)
        #expect(d.category == .simdAndFP)
    }

    @Test func fpDataProcessing1SourceRoute() {
        let d = decode(0x1E60_C020, at: 0)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fpCompareRoute() {
        let d = decode(0x1E62_2020, at: 0)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func fpImmediateRoute() {
        let d = decode(0x1E70_1000, at: 0)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fpConditionalCompareRoute() {
        let d = decode(0x1E62_0420, at: 0)
        #expect(d.mnemonic == .fccmp)
    }

    @Test func fpConditionalSelectRoute() {
        let d = decode(0x1E62_0C20, at: 0)
        #expect(d.mnemonic == .fcsel)
    }

    @Test func fpDataProcessing3SourceRoute() {
        let d = decode(0x1F02_0C20, at: 0)
        #expect(d.mnemonic == .fmadd)
    }

    @Test func fpFixedPointConversionRoute() {
        let d = decode(0x9E42_FC20, at: 0)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func fpIntegerConversionRoute() {
        let d = decode(0x9E78_0020, at: 0)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func advSIMDVectorThreeSameRoute() {
        let d = decode(0x0E22_8420, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func advSIMDVectorThreeDifferentRoute() {
        let d = decode(0x0E22_0020, at: 0)
        #expect(d.mnemonic == .saddl)
    }

    @Test func advSIMDVectorTwoRegMiscRoute() {
        let d = decode(0x0E20_0820, at: 0)
        #expect(d.mnemonic == .rev64)
    }

    @Test func advSIMDVectorAcrossLanesRoute() {
        let d = decode(0x0E30_3820, at: 0)
        #expect(d.mnemonic == .saddlv)
    }

    @Test func advSIMDVectorCopyRoute() {
        let d = decode(0x0E01_0420, at: 0)
        #expect(d.mnemonic == .dup)
    }

    @Test func advSIMDVectorPermuteRoute() {
        let d = decode(0x0E02_1820, at: 0)
        #expect(d.mnemonic == .uzp1)
    }

    @Test func advSIMDVectorExtractRoute() {
        let d = decode(0x2E02_0820, at: 0)
        #expect(d.mnemonic == .ext)
    }

    @Test func advSIMDTableLookupRoute() {
        let d = decode(0x0E02_0020, at: 0)
        #expect(d.mnemonic == .tbl)
    }

    @Test func advSIMDVectorThreeRegExtensionRoute() {
        let d = decode(0x0E82_9420, at: 0)
        #expect(d.mnemonic == .sdot)
    }

    @Test func advSIMDVectorModifiedImmediateRoute() {
        let d = decode(0x0F00_0400, at: 0)
        #expect(d.mnemonic == .movi)
    }

    @Test func advSIMDVectorShiftByImmediateRoute() {
        let d = decode(0x0F0F_0420, at: 0)
        #expect(d.mnemonic == .sshr)
    }

    @Test func advSIMDVectorXIndexedElementRoute() {
        let d = decode(0x0F42_8020, at: 0)
        #expect(d.mnemonic == .mul)
    }

    @Test func advSIMDScalarThreeSameRoute() {
        let d = decode(0x5EE2_8420, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func advSIMDScalarThreeDifferentRoute() {
        let d = decode(0x5EA2_9020, at: 0)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func advSIMDScalarTwoRegMiscRoute() {
        let d = decode(0x5EE0_7820, at: 0)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func advSIMDScalarPairwiseRoute() {
        let d = decode(0x5EF1_B820, at: 0)
        #expect(d.mnemonic == .addp)
    }

    @Test func advSIMDScalarCopyRoute() {
        let d = decode(0x5E01_0420, at: 0)
        #expect(d.mnemonic == .mov)
    }

    @Test func advSIMDScalarShiftByImmediateRoute() {
        let d = decode(0x5F7F_0420, at: 0)
        #expect(d.mnemonic == .sshr)
    }

    @Test func advSIMDScalarXIndexedElementRoute() {
        let d = decode(0x5F82_9020, at: 0)
        #expect(d.mnemonic == .fmul)
    }

    @Test func op0_0x6_V1RoutesToVectorLoadStore() {
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.category == .simdAndFP)
        #expect(d.mnemonic == .st4)
    }
}

/// Validates `decodeVectorLoadStore`, the V=1 entry called from the L/S
/// decoder, dispatching by bits[29:24].
@Suite("SIMD/FP / decodeVectorLoadStore dispatch")
struct DecodeVectorLoadStoreTests {
    @Test func advSIMDMultiStructureNoOffsetRoute() {
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.mnemonic == .st4)
    }

    @Test func advSIMDMultiStructurePostIndexedRoute() {
        let d = decode(0x0C9F_0000, at: 0)
        #expect(d.mnemonic == .st4)
    }

    @Test func advSIMDSingleStructureNoOffsetRoute() {
        let d = decode(0x0D00_0000, at: 0)
        #expect(d.mnemonic == .st1)
    }

    @Test func advSIMDSingleStructurePostIndexedRoute() {
        let d = decode(0x0D9F_0000, at: 0)
        #expect(d.mnemonic == .st1)
    }

    @Test func scalarSIMDLiteralLoadRoute() {
        let d = decode(0x1C00_0000, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func scalarSIMDLoadStorePairLDNPRoute() {
        let d = decode(0x2C00_0400, at: 0)
        #expect(d.mnemonic == .stnp)
    }

    @Test func scalarSIMDLoadStorePairLDPPostIndexedRoute() {
        let d = decode(0x2CC0_0400, at: 0)
        #expect(d.mnemonic == .ldp)
    }

    @Test func scalarSIMDLoadStorePairLDPSignedOffsetRoute() {
        let d = decode(0x2D40_0400, at: 0)
        #expect(d.mnemonic == .ldp)
    }

    @Test func scalarSIMDLoadStorePairSTPPreIndexedRoute() {
        let d = decode(0x2D80_0400, at: 0)
        #expect(d.mnemonic == .stp)
    }

    @Test func scalarSIMDLoadStoreIndexedRoute() {
        let d = decode(0xBC00_0000, at: 0)
        #expect(d.mnemonic == .stur)
    }

    @Test func scalarSIMDLoadStoreUnsignedOffsetRoute() {
        let d = decode(0xBD00_0000, at: 0)
        #expect(d.mnemonic == .str)
    }
}

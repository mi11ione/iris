// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the SIMD/FP family's place in the standard composition —
/// op0 ∈ {0x7, 0xF} attribute to the family, plus the V=1 load/store
/// delegation from the L/S slab — asserted through public category
/// attribution.
@Suite("SIMD/FP / SIMDAndFPDecoder family registration")
struct SIMDAndFPDecoderRegistrationTests {
    @Test func bothSIMDFPOp0PartitionsAttributeToTheFamily() {
        #expect(decode(0x0E20_1C00).category == .simdAndFP) // op0=0x7 and v0.8b
        #expect(decode(0x1E20_1000).category == .simdAndFP) // op0=0xF fmov s0
    }
}

/// Validates the SIMDAndFPDecoder.decode dispatch into each AdvSIMD /
/// FP scalar sub-class. Each test crafts an encoding that lands in
/// exactly one sub-decoder and verifies the resulting mnemonic — the
/// hand-off, not the per-class operand shape (covered by per-decoder
/// suites).
@Suite("SIMD/FP / Top-level decode routing")
struct SIMDAndFPDecoderRoutingTests {
    @Test func fpDataProcessing2SourceRoute() {
        // FADD D0, D1, D2 — bits[31:24]=0x1E, bit[21]=1, bits[14:10]=0b00110,
        // opcode=0010 (FADD). bits[11:10]=10, dispatch picks FP DP 2-source.
        let d = decode(0x1E62_2820, at: 0)
        #expect(d.mnemonic == .fadd)
        #expect(d.category == .simdAndFP)
    }

    @Test func fpDataProcessing1SourceRoute() {
        // FABS D0, D1 — opcode 000001, bits[14:10]=10000.
        let d = decode(0x1E60_C020, at: 0)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fpCompareRoute() {
        // FCMP D1, D2 — bits[15:10]=001000, opc=00.
        let d = decode(0x1E62_2020, at: 0)
        #expect(d.mnemonic == .fcmp)
    }

    @Test func fpImmediateRoute() {
        // FMOV D0, #1.0 — bits[12:10]=100 with bit[12]=1, imm8=0x70, imm5=0.
        let d = decode(0x1E70_1000, at: 0)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fpConditionalCompareRoute() {
        // FCCMP D1, D2, #0, EQ — bits[11:10]=01.
        let d = decode(0x1E62_0420, at: 0)
        #expect(d.mnemonic == .fccmp)
    }

    @Test func fpConditionalSelectRoute() {
        // FCSEL D0, D1, D2, EQ — bits[11:10]=11.
        let d = decode(0x1E62_0C20, at: 0)
        #expect(d.mnemonic == .fcsel)
    }

    @Test func fpDataProcessing3SourceRoute() {
        // FMADD D0, D1, D2, D3 — bits[31:24]=0x1F.
        let d = decode(0x1F02_0C20, at: 0)
        #expect(d.mnemonic == .fmadd)
    }

    @Test func fpFixedPointConversionRoute() {
        // SCVTF D0, X1, #1 — sf=1 rmode=00 opcode=010 scale=63 (fbits=1).
        // bits[31:24]=0x9E, bit[21]=0 (fixed-point).
        let d = decode(0x9E42_FC20, at: 0)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func fpIntegerConversionRoute() {
        // FCVTZS X0, D1 — sf=1, ftype=01 (D), rmode=11, opcode=000.
        let d = decode(0x9E78_0020, at: 0)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func advSIMDVectorThreeSameRoute() {
        // ADD V0.8B, V1.8B, V2.8B — bits[31:24]=0x0E, bit[21]=1, bit[10]=1.
        let d = decode(0x0E22_8420, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func advSIMDVectorThreeDifferentRoute() {
        // SADDL V0.8H, V1.8B, V2.8B — bit[10]=0, bit[11]=0.
        let d = decode(0x0E22_0020, at: 0)
        #expect(d.mnemonic == .saddl)
    }

    @Test func advSIMDVectorTwoRegMiscRoute() {
        // REV64 V0.8B, V1.8B — bit[21]=1, bit[11]=1, bit[10]=0, bits[20:17]=1000.
        // Encoding: bits[31:24]=0x0E, bits[16:12]=opcode=00000 (REV64).
        let d = decode(0x0E20_0820, at: 0)
        #expect(d.mnemonic == .rev64)
    }

    @Test func advSIMDVectorAcrossLanesRoute() {
        // SADDLV H0, V1.8B — bit[21]=1, bits[20:17]=1100, opcode=00011.
        let d = decode(0x0E30_3820, at: 0)
        #expect(d.mnemonic == .saddlv)
    }

    @Test func advSIMDVectorCopyRoute() {
        // DUP V0.8B, V1.B[0] — bit[21]=0, bit[15]=0, bit[10]=1.
        let d = decode(0x0E01_0420, at: 0)
        #expect(d.mnemonic == .dup)
    }

    @Test func advSIMDVectorPermuteRoute() {
        // UZP1 V0.8B, V1.8B, V2.8B — bit[21]=0, bit[15]=0, bit[11]=1,
        // bit[10]=0, opcode=001.
        let d = decode(0x0E02_1820, at: 0)
        #expect(d.mnemonic == .uzp1)
    }

    @Test func advSIMDVectorExtractRoute() {
        // EXT V0.8B, V1.8B, V2.8B, #1 — bit[15]=0, bit[11]=0, bit[10]=0,
        // bit[29:28]=10. Encoding: 0x2E02_0820.
        let d = decode(0x2E02_0820, at: 0)
        #expect(d.mnemonic == .ext)
    }

    @Test func advSIMDTableLookupRoute() {
        // TBL V0.8B, {V1.16B}, V2.8B — bit[29:28]=00 (TBL distinguishes
        // from EXT by bit[29]=0). bit[15]=0, bit[11]=0, bit[10]=0.
        let d = decode(0x0E02_0020, at: 0)
        #expect(d.mnemonic == .tbl)
    }

    @Test func advSIMDVectorThreeRegExtensionRoute() {
        // SDOT V0.2S, V1.8B, V2.8B.
        let d = decode(0x0E82_9420, at: 0)
        #expect(d.mnemonic == .sdot)
    }

    @Test func advSIMDVectorModifiedImmediateRoute() {
        // MOVI V0.2S, #0 — bits[31:24]=0x0F, bits[23:19]=00000.
        let d = decode(0x0F00_0400, at: 0)
        #expect(d.mnemonic == .movi)
    }

    @Test func advSIMDVectorShiftByImmediateRoute() {
        // SSHR V0.8B, V1.8B, #1 — bits[31:24]=0x0F, immh=0001, bit[10]=1.
        let d = decode(0x0F0F_0420, at: 0)
        #expect(d.mnemonic == .sshr)
    }

    @Test func advSIMDVectorXIndexedElementRoute() {
        // MUL V0.4H, V1.4H, V2.H[0] — bits[31:24]=0x0F, immh=0001 ↛ shift,
        // bit[10]=0 ↛ xIndexed.
        let d = decode(0x0F42_8020, at: 0)
        #expect(d.mnemonic == .mul)
    }

    @Test func advSIMDScalarThreeSameRoute() {
        // ADD D0, D1, D2 — bits[31:24]=0x5E, bit[21]=1, bit[10]=1.
        let d = decode(0x5EE2_8420, at: 0)
        #expect(d.mnemonic == .add)
    }

    @Test func advSIMDScalarThreeDifferentRoute() {
        // SQDMLAL D0, S1, S2 — opcode=1001, bit[10]=0, bit[11]=0.
        let d = decode(0x5EA2_9020, at: 0)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func advSIMDScalarTwoRegMiscRoute() {
        // SQABS D0, D1 — bits[20:17]=1000, bit[11]=1, bit[10]=0, U=0,
        // opcode=00111.
        let d = decode(0x5EE0_7820, at: 0)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func advSIMDScalarPairwiseRoute() {
        // ADDP D0, V1.2D — bits[20:17]=1100, opcode=11011.
        let d = decode(0x5EF1_B820, at: 0)
        #expect(d.mnemonic == .addp)
    }

    @Test func advSIMDScalarCopyRoute() {
        // DUP B0, V1.B[0] — bits[31:24]=0x5E, bit[21]=0; alias = MOV.
        let d = decode(0x5E01_0420, at: 0)
        #expect(d.mnemonic == .mov)
    }

    @Test func advSIMDScalarShiftByImmediateRoute() {
        // SSHR D0, D1, #1 — bits[31:24]=0x5F, immh=1000, opcode=00000, bit[10]=1.
        let d = decode(0x5F7F_0420, at: 0)
        #expect(d.mnemonic == .sshr)
    }

    @Test func advSIMDScalarXIndexedElementRoute() {
        // FMUL S0, S1, V2.S[0] — bits[31:24]=0x5F, immh=1000, bit[10]=0,
        // opcode=1001, sz=0.
        let d = decode(0x5F82_9020, at: 0)
        #expect(d.mnemonic == .fmul)
    }

    @Test func op0_0x6_V1RoutesToVectorLoadStore() {
        // op0=0x6 with V=1 — AdvSIMD multi-structure load/store shell.
        // bits[29:24] = 001100 — AdvSIMD multi-structure (st4).
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.category == .simdAndFP)
        #expect(d.mnemonic == .st4)
    }
}

/// Validates SIMDAndFPDecoder.decodeVectorLoadStore — the V=1 delegation
/// entry called from LoadsAndStoresDecoder. Sub-class
/// dispatch by bits[29:24].
@Suite("SIMD/FP / decodeVectorLoadStore dispatch")
struct DecodeVectorLoadStoreTests {
    @Test func advSIMDMultiStructureNoOffsetRoute() {
        // bits[29:24]=001100 → ST4 / LD4 / ... by opcode.
        // ST4 {V0.8B-V3.8B}, [X0]: opcode=0000, L=0, size=00, Q=0.
        let d = decode(0x0C00_0000, at: 0)
        #expect(d.mnemonic == .st4)
    }

    @Test func advSIMDMultiStructurePostIndexedRoute() {
        // bits[29:24]=001110 → post-indexed multi-structure.
        // ST4 {V0.8B-V3.8B}, [X0], #32: Rm=11111 (immediate-form).
        let d = decode(0x0C9F_0000, at: 0)
        #expect(d.mnemonic == .st4)
    }

    @Test func advSIMDSingleStructureNoOffsetRoute() {
        // bits[29:24]=001101 → single-structure no-offset.
        // ST1 {V0.B}[0], [X0]: opcode=000, R=0, L=0, S=0, size=00.
        let d = decode(0x0D00_0000, at: 0)
        #expect(d.mnemonic == .st1)
    }

    @Test func advSIMDSingleStructurePostIndexedRoute() {
        // bits[29:24]=001111 → single-structure post-indexed.
        let d = decode(0x0D9F_0000, at: 0)
        #expect(d.mnemonic == .st1)
    }

    @Test func scalarSIMDLiteralLoadRoute() {
        // bits[29:24]=011000 → scalar LDR literal.
        // LDR S0, label: opc=00 (S).
        let d = decode(0x1C00_0000, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func scalarSIMDLoadStorePairLDNPRoute() {
        // bits[29:24]=101000 → LDNP/STNP. STNP S0, S1, [X0]: opc=00 L=0.
        let d = decode(0x2C00_0400, at: 0)
        #expect(d.mnemonic == .stnp)
    }

    @Test func scalarSIMDLoadStorePairLDPPostIndexedRoute() {
        // V=1 LDP post-indexed: bits[29:24]=101100 (bit 24 = 0),
        // bits[24:23] = 01 (post), L=1. Byte 1 = 1100_0000 = 0xC0.
        let d = decode(0x2CC0_0400, at: 0)
        #expect(d.mnemonic == .ldp)
    }

    @Test func scalarSIMDLoadStorePairLDPSignedOffsetRoute() {
        // bits[29:24]=101010.
        let d = decode(0x2D40_0400, at: 0)
        #expect(d.mnemonic == .ldp)
    }

    @Test func scalarSIMDLoadStorePairSTPPreIndexedRoute() {
        // bits[29:24]=101011.
        let d = decode(0x2D80_0400, at: 0)
        #expect(d.mnemonic == .stp)
    }

    @Test func scalarSIMDLoadStoreIndexedRoute() {
        // bits[29:24]=111000 → indexed/unscaled/register-offset/pre-/post-.
        // STUR S0, [X0, #0]: size=10 opc=00 bits[11:10]=00.
        let d = decode(0xBC00_0000, at: 0)
        #expect(d.mnemonic == .stur)
    }

    @Test func scalarSIMDLoadStoreUnsignedOffsetRoute() {
        // bits[29:24]=111001 → unsigned-offset.
        let d = decode(0xBD00_0000, at: 0)
        #expect(d.mnemonic == .str)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func decodeLS(_ encoding: UInt32) -> Instruction {
    decode(encoding, at: 0)
}

/// Validates malformed / reserved encodings produce UNDEFINED across every
/// SIMD/FP sub-decoder. Each test crafts a specific reserved bit pattern
/// that should hit a guard inside the corresponding decoder.
@Suite("SIMD/FP / Reserved encoding behaviour")
struct SIMDFPReservedEncodingTests {
    /// AdvSIMDExtractDecode L22 — op2 != 0 reserved.
    @Test func extractOp2NonZeroIsUndefined() {
        // op2 = bits[23:22] = 01 instead of 00. Top byte 0x2E unchanged,
        // byte 1 needs bit 22 = 1 ⇒ 0100_0010 = 0x42.
        let d = decode(0x2E42_0820)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDPermuteDecode L27 — .d1 arrangement reserved.
    @Test func permuteWithD1ArrangementIsUndefined() {
        // UZP1 V0.1D, ...: size=11 Q=0 ⇒ .d1 reserved. Encoding needs
        // bit 21 = 0 (permute pattern); byte 1 = 1100_0010 = 0xC2.
        let d = decode(0x0EC2_1820)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDCopyDecode L87 — DUP general D-element with Q=0 reserved.
    @Test func dupGeneralDElementQZeroIsUndefined() {
        // imm5=01000 (D), imm4=0001 (DUP general), Q=0.
        let d = decode(0x0E08_0C20)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDCopyDecode decodeElementSizeAndIndex — imm5 = 0b10000 (only
    /// bit 4 set) selects no element type → undefined.
    @Test func dupElementWithImm5Bit4OnlyIsUndefined() {
        // imm5=10000: bit 20 = 1, other imm5 bits zero. byte 1 = 0001_0000.
        let d = decode(0x0E10_0420)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDScalarCopyDecode decodeElementSizeAndIndex — same
    /// imm5=0b10000 case but for scalar tier (top byte 0x5E).
    @Test func dupScalarWithImm5Bit4OnlyIsUndefined() {
        let d = decode(0x5E10_0420)
        #expect(d.mnemonic == .undefined)
    }

    /// SIMDAndFPDecoder.dispatchAdvSIMDScalar0xX_E — bit21=1 bit10=0
    /// bit11=1 with bits20_17 ∉ {0000, 1000} hits the final undefined.
    @Test func scalarTierTwoRegMiscReservedBits20_17IsUndefined() {
        // top byte 0x5E. byte 1 = 1110_0010 = 0xE2 (size=11, bit21=1,
        // bits[20:17]=0001). byte 2 = 1000_1000 = 0x88 (opcode bits=1000,
        // bit11=1, bit10=0).
        let d = decode(0x5EE2_8820)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDThreeSameDecode.intMnemonic — (U=1, opcode=10111) reserved
    /// (no integer-family mnemonic mapping). Hits the `guard let m`
    /// undefined path.
    @Test func vectorThreeSameU1Opcode10111IsUndefined() {
        // U=1, opcode=10111, size=00 ⇒ byte 0 = 0010_1110 = 0x2E.
        // byte 2 = 1011_1100 = 0xBC.
        let d = decode(0x2E22_BC20)
        #expect(d.mnemonic == .undefined)
    }

    /// SIMDAndFPDecoder.dispatchVectorNonThreeArg — bit15=1, bit10=0
    /// reserved (not three-reg-extension or any other class).
    @Test func vectorNonThreeArgBit15OneBit10ZeroReserved() {
        // top byte 0x0E. byte 1: bit 21 = 0 → 0x00. byte 2: bit 15 = 1,
        // bit 10 = 0 → 1000_0000 = 0x80.
        let d = decode(0x0E00_8000)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDLoadStoreSingleStructureDecode.singleStructLayout — store
    /// (L=0) with replicate opcode=0b111 has no architectural meaning
    /// (ST3R/ST4R don't exist). Hits the default `return nil`.
    @Test func singleStructureReplicateStore111IsUndefined() {
        // opcode=111, R=0, L=0. byte 1 = 0x00. byte 2 = 1110_0000 = 0xE0.
        let d = decodeLS(0x0D00_E000)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDTwoRegMiscDecode.decodeFPFamily — 0x2E21E820 decodes as FRINT32X
    /// (FEAT_FRINTTS), matching llvm-mc; it is not a reserved triple.
    @Test func vectorTwoRegMiscFrint32xDecodes() {
        let d = decode(0x2E21_E820)
        #expect(d.mnemonic == .frint32x)
    }

    /// AdvSIMDThreeSameDecode.arrangementValidForIntOpcode — SHADD with
    /// .2D arrangement (size=11 Q=1) is reserved.
    @Test func shaddOf_2DIsReserved() {
        let d = decode(0x4EE2_0420)
        #expect(d.mnemonic == .undefined)
    }

    /// AdvSIMDLoadStoreSingleStructureDecode — post-indexed with register Rm.
    @Test func singleStructurePostIndexedRegisterRm() {
        // ST1 V0.B[0], [X0], X3: op0=6 single-structure shell (top byte
        // 0x0D), bit23 = postIndexed, Rm=3.
        // byte 1 = 1_0_0_00011 = 1000_0011 = 0x83. byte 2 = 0. byte 3 = 0.
        let d = decodeLS(0x0D83_0000)
        #expect(d.mnemonic == .st1)
        // Should have Rm read in semantic reads.
        #expect(d.semanticReads.contains(.x(3)))
    }

    /// AdvSIMDLoadStoreSingleStructureDecode L200..204 — opcode=011 (3-struct H/S/D).
    @Test func ld3SingleStructureHalfwordElement() {
        // LD3 {V0-V2}.H[0], [X0]: opcode=011, R=0, L=1. byte 2: 0110_0000 = 0x60.
        let d = decodeLS(0x0D40_6000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func ld4SingleStructureHalfwordElement() {
        // LD4 {V0-V3}.H[0]: opcode=011, R=1.
        let d = decodeLS(0x0D60_6000)
        #expect(d.mnemonic == .ld4)
    }

    @Test func st3SingleStructureWordElement() {
        // ST3: opcode=101, R=0, L=0. byte 2: 1010_0000 = 0xA0.
        let d = decodeLS(0x0D00_A000)
        #expect(d.mnemonic == .st3)
    }

    @Test func st4SingleStructureWordElement() {
        let d = decodeLS(0x0D20_A000)
        #expect(d.mnemonic == .st4)
    }

    /// AdvSIMDLoadStoreSingleStructureDecode — ld3r/ld4r with R=1.
    @Test func ld4ReplicateAllLanes() {
        // LD4R: opcode=111, R=1, L=1.
        let d = decodeLS(0x0D60_E000)
        #expect(d.mnemonic == .ld4r)
    }

    /// AdvSIMDShiftByImmediateDecode L37 — H-element branch.
    @Test func shiftByImmediateHalfElement() {
        // SSHR V0.4H, V1.4H, #1: immh=0010, immb=111.
        // byte 1 = 0_0010_111 = 0001_0111 = 0x17.
        // byte 2 = 00000_1_00 = 0x04.
        let d = decode(0x0F17_0420)
        #expect(d.mnemonic == .sshr)
    }

    /// AdvSIMDModifiedImmediateDecode L159 — classifyImmediate cmode=1111 op=1 Q=0
    /// returns nil (reserved).
    @Test func fmovImmediate2DWithQZeroIsUndefined() {
        // FMOV .2D with Q=0 reserved.
        let d = decode(0x2F00_F400)
        #expect(d.mnemonic == .undefined)
    }

    /// FPIntegerConversionDecode — ftype=11 with rmode/opcode that doesn't match any
    /// FCVT/SCVTF/FMOV variant returns undefined.
    @Test func fpIntegerConversionUnmatchedReturnsUndefined() {
        // ftype=11 (H), rmode=10, opcode=100 — not in FCVT family table.
        let d = decode(0x9EF4_0020)
        #expect(d.mnemonic == .undefined)
    }

    /// SIMDAndFPDecoder L342 — dispatchFPScalar0x1E case bits[11:10] = 00 with no
    /// FP-compare/FP-immediate match returns undefined.
    @Test func fpScalarBits1110Zero00WithoutCompareOrImmediateIsUndefined() {
        // bits[15:10] = 011000 with bit 12 = 0 and bits[11:10] = 00 matches
        // neither the FP-compare row (001000) nor the FP-immediate route
        // (bit 12 = 1) ⇒ falls through to the undefined return.
        let d = decode(0x1E60_6020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedShapeWordsAcrossTheFamilyDecodeUndefined() {
        // Every word here is rejected by llvm-mc 22.1.4 at the maximal
        // feature set; each exercises one reserved-shape guard:
        let words: [UInt32] = [
            0x0F00_9C20, // modified-immediate o2=1 with cmode != 1111
            0x5FC0_0420, // scalar shift-by-imm bit23 = 1
            0x5F08_E420, // scalar SCVTF shift-by-imm with B element
            0x5F48_9420, // scalar narrowing shift with D destination
            0x5E20_8820, // scalar CMGT at size 00 (D-only op)
            0x5EE1_4820, // scalar SQXTN at size 11
            0x5F42_1020, // scalar FMLA by-element at size 01
            0x5FE2_1020, // scalar FMLA by-element D with L = 1
            0x0F88_0420, // vector shift-by-imm bit23 = 1
            0x0F48_9420, // vector narrowing shift with D destination
            0x0F08_E420, // vector SCVTF shift-by-imm with B element
            0x0EE0_B820, // ABS .1d (size=11, Q=0 same-shape)
            0x2EE2_3C20, // FP three-same (U=1, opcode 01111, alt) unallocated
            0x6F42_B020, // by-element (U=1, opcode 1011) unallocated
            0x6FA2_3020, // by-element FCMLA .4s with L = 1
            0x0E70_C820, // FP across-lanes with size<0> = 1
            0x2E30_C820, // FP32 across-lanes with Q = 0
            0x9F02_0C20, // FMADD with M = 1
            0x1E66_0020, // FMOV D↔W width mismatch (sf = 0)
            0x3E21_2020, // FP scalar class with S = 1
            0x9E21_2020, // FP-DP scalar with M = 1
            0x1EE8_4020, // FRINT32Z scalar at ftype 11 (half)
            0xBCC0_0420, // scalar SIMD indexed with reserved (size, opc)
            0x8C40_7000, // multi-structure with bit31 = 1
            0x0C60_7000, // multi-structure with bit21 = 1
            0x0C41_7000, // multi-structure no-offset with Rm != 0
            0x0C00_1000, // multi-structure reserved opcode 0001
            0x8D40_8420, // single-structure with bit31 = 1
            0x0D42_0000, // single-structure no-offset with Rm = 2
            0x0D40_D000, // LD1R with S = 1
            0x0D40_8800, // single-structure word/dword form with size<1> = 1
            0x0D00_C000, // single-structure reserved store-replicate opcode
            0x6F03_FE00, // FMOV vector immediate with op=1 and o2=1
            0x5E22_3420, // scalar CMGT (register) at size 00
            0x0EA2_E420, // FP three-same (U=0, opcode 11100, alt) unallocated
            0x3C60_0020, // scalar SIMD unscaled-immediate with bit21 = 1
        ]
        for word in words {
            let d = decode(word)
            #expect(d.isUndefined, "0x\(String(word, radix: 16))")
            #expect(d.encoding == word)
        }
    }

    /// The 0xX_E vector shell's bit21=0 / bit15=1 / bit10=0 arm carries no
    /// allocated encodings — llvm-mc 22.1.4 rejects 0x0E008000.
    @Test func vectorNonThreeArgBit15SetBit10ClearReservedIsUndefined() {
        let d = decode(0x0E00_8000)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .undefined)
        #expect(d.encoding == 0x0E00_8000)
    }
}

/// Validates sign extension via negative imm immediates in V=1 L/S
/// classes — covers `lsSignExtendImm19/9/7Local` else-branches.
@Suite("SIMD/FP / V=1 L/S negative immediates")
struct SIMDFPNegativeImmediateTests {
    /// ScalarSIMDLoadLiteralDecode L49 — negative imm19.
    @Test func ldrLiteralNegativeOffset() {
        // LDR S0, label with imm19 high bit set (negative offset).
        // bits[29:24]=011100, bits[23:5] = imm19 with bit 23 = 1 ⇒ negative.
        // top byte 0x1C. byte 1 = 1111_1111 = 0xFF (imm19 high bits all 1).
        let d = decode(0x1CFF_FFE0, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    /// ScalarSIMDLoadStoreIndexedDecode L163 — negative imm9.
    @Test func sturNegativeImm9() {
        // STUR S0, [X0, #-1]: V=1 scalar unscaled store, imm9 = -1 (0x1FF).
        let d = decode(0xBC1F_F000, at: 0)
        #expect(d.mnemonic == .stur)
    }

    /// ScalarSIMDLoadStorePairDecode L91 — negative imm7.
    @Test func stpNegativeImm7() {
        // STP S0, S1, [X0, #-4]: imm7 = signed -1 with sf=0. scale=4 ⇒ disp = -4.
        // signed-offset indexing=10: bit 24 = 1. top byte (opc=00) = 0010_1101 = 0x2D.
        // byte 1: bit 23 = 0, bit 22 = L = 0, imm7 high = 1_111111 = 0x7F.
        // byte 1 = 00_111111 = 0011_1111 = 0x3F. byte 2 = 1_00001_00 = 1000_0100 = 0x84.
        let d = decode(0x2D3F_8400, at: 0)
        #expect(d.mnemonic == .stp)
    }
}

/// Validates simdfpGprOperand with encoding=31 — sp/wsp or zr branch.
@Suite("SIMD/FP / GPR encoding 31 mapping")
struct SIMDFPGprEncoding31Tests {
    /// ScalarSIMD LDR/STR with Rn=31 (SP/WSP base).
    @Test func ldrWithSPBase() {
        // LDR S0, [SP]: Rn=31 spOrGeneral=true ⇒ SP. unsigned offset.
        // top byte 0xBD. byte 3: bit 5..9 = Rn = 11111. byte 3 = 0011_1110 = 0x3E.
        let d = decode(0xBD40_03E0, at: 0)
        #expect(d.mnemonic == .ldr)
    }

    /// SCVTF S0, WZR, #1 — Rn=31 spOrGeneral=false ⇒ WZR.
    @Test func scvtfFixedWithWZRSource() {
        // SCVTF (fixed, sf=0): scale must be ≥ 33; scale=33 ⇒ fbits=31.
        // Rn=11111 in the GPR source slot reads WZR (not SP) ⇒ 0x1E02_843E.
        let d = decode(0x1E02_843E)
        #expect(d.mnemonic == .scvtf)
    }
}

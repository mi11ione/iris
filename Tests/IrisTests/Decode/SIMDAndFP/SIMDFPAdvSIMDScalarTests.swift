// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD scalar three-same — saturating arithmetic, compares,
/// shifts, SQDMULH, SQRDMULH, plus FP family (FMULX, FCMEQ, FRECPS,
/// FRSQRTS, FCMGE, FACGE, FACGT, FABD, FCMGT).
@Suite("SIMD/FP / AdvSIMD scalar three-same")
struct AdvSIMDScalarThreeSameTests {
    @Test func sqaddDoubleScalar() {
        // SQADD D0, D1, D2: U=0, size=11, opcode=00001, Rm=2.
        // top byte 0x5E. byte 1: 11_1_00010 = 1110_0010 = 0xE2.
        // byte 2: 00001_1_00 = 0000_1100 = 0x0C. byte 3: 0x20.
        let d = decode(0x5EE2_0C20)
        #expect(d.mnemonic == .sqadd)
    }

    @Test func uqaddDoubleScalar() {
        let d = decode(0x7EE2_0C20)
        #expect(d.mnemonic == .uqadd)
    }

    @Test func sqsubDoubleScalar() {
        // opcode=00101.
        let d = decode(0x5EE2_2C20)
        #expect(d.mnemonic == .sqsub)
    }

    @Test func uqsubDoubleScalar() {
        let d = decode(0x7EE2_2C20)
        #expect(d.mnemonic == .uqsub)
    }

    @Test func cmgtDoubleScalar() {
        // opcode=00110.
        let d = decode(0x5EE2_3420)
        #expect(d.mnemonic == .cmgt)
    }

    @Test func cmgeDoubleScalar() {
        let d = decode(0x5EE2_3C20)
        #expect(d.mnemonic == .cmge)
    }

    @Test func sshlDoubleScalar() {
        // opcode=01000.
        let d = decode(0x5EE2_4420)
        #expect(d.mnemonic == .sshl)
    }

    @Test func sqshlDoubleScalar() {
        let d = decode(0x5EE2_4C20)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func srshlDoubleScalar() {
        let d = decode(0x5EE2_5420)
        #expect(d.mnemonic == .srshl)
    }

    @Test func sqrshlDoubleScalar() {
        let d = decode(0x5EE2_5C20)
        #expect(d.mnemonic == .sqrshl)
    }

    @Test func ushlDoubleScalar() {
        let d = decode(0x7EE2_4420)
        #expect(d.mnemonic == .ushl)
    }

    @Test func uqshlDoubleScalar() {
        let d = decode(0x7EE2_4C20)
        #expect(d.mnemonic == .uqshl)
    }

    @Test func urshlDoubleScalar() {
        let d = decode(0x7EE2_5420)
        #expect(d.mnemonic == .urshl)
    }

    @Test func uqrshlDoubleScalar() {
        let d = decode(0x7EE2_5C20)
        #expect(d.mnemonic == .uqrshl)
    }

    @Test func addDoubleScalar() {
        // opcode=10000.
        let d = decode(0x5EE2_8420)
        #expect(d.mnemonic == .add)
    }

    @Test func subDoubleScalar() {
        let d = decode(0x7EE2_8420)
        #expect(d.mnemonic == .sub)
    }

    @Test func cmtstDoubleScalar() {
        // opcode=10001.
        let d = decode(0x5EE2_8C20)
        #expect(d.mnemonic == .cmtst)
    }

    @Test func cmeqDoubleScalar() {
        let d = decode(0x7EE2_8C20)
        #expect(d.mnemonic == .cmeq)
    }

    @Test func cmhiDoubleScalar() {
        let d = decode(0x7EE2_3420)
        #expect(d.mnemonic == .cmhi)
    }

    @Test func cmhsDoubleScalar() {
        let d = decode(0x7EE2_3C20)
        #expect(d.mnemonic == .cmhs)
    }

    @Test func sqdmulhHalfScalar() {
        // SQDMULH H0, H1, H2: U=0, size=01 (H), opcode=10110.
        // byte 1: 01_1_00010 = 0110_0010 = 0x62.
        // byte 2: 10110_1_00 = 1011_0100 = 0xB4.
        let d = decode(0x5E62_B420)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhHalfScalar() {
        let d = decode(0x7E62_B420)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func fmulxScalarSingle() {
        // FMULX S0, S1, S2: U=0, sz=0, opcode=11011, altBit=0.
        // size=00 ⇒ byte 1 = 00_1_00010 = 0x22. byte 2: 11011_1_00 = 1101_1100 = 0xDC.
        let d = decode(0x5E22_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcmeqScalarSingle() {
        // FCMEQ: U=0, opcode=11100.
        // byte 2: 11100_1_00 = 1110_0100 = 0xE4.
        let d = decode(0x5E22_E420)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func frecpsScalarSingle() {
        // FRECPS: U=0, opcode=11111, altBit=0.
        let d = decode(0x5E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func frsqrtsScalarSingle() {
        // FRSQRTS: U=0, opcode=11111, altBit=1.
        // size=10 ⇒ byte 1 = 10_1_00010 = 0xA2.
        let d = decode(0x5EA2_FC20)
        #expect(d.mnemonic == .frsqrts)
    }

    @Test func fcmgeScalarSingle() {
        let d = decode(0x7E22_E420)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmgtScalarSingle() {
        // FCMGT: U=1, opcode=11100, altBit=1.
        let d = decode(0x7EA2_E420)
        #expect(d.mnemonic == .fcmgt)
    }

    @Test func facgeScalarSingle() {
        // FACGE: U=1, opcode=11101, altBit=0.
        let d = decode(0x7E22_EC20)
        #expect(d.mnemonic == .facge)
    }

    @Test func facgtScalarSingle() {
        // FACGT: U=1, opcode=11101, altBit=1.
        let d = decode(0x7EA2_EC20)
        #expect(d.mnemonic == .facgt)
    }

    @Test func fabdScalarSingle() {
        // FABD: U=1, opcode=11010, altBit=1.
        let d = decode(0x7EA2_D420)
        #expect(d.mnemonic == .fabd)
    }

    @Test func reservedFPSizeReturnsUndefined() {
        // FP scalar three-same with no matching (U, opcode, altBit).
        // U=0 opcode=11100 altBit=1 — no case.
        let d = decode(0x5EA2_E420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        // U=0 opcode=10100 (no match in integer mapping).
        let d = decode(0x5EE2_A420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar three-different — SQDMLAL/SQDMLSL/SQDMULL.
@Suite("SIMD/FP / AdvSIMD scalar three-different")
struct AdvSIMDScalarThreeDifferentTests {
    @Test func sqdmlalScalarHToS() {
        // SQDMLAL S0, H1, H2: size=01, opcode=1001.
        // byte 1: 01_1_00010 = 0x62. byte 2: 1001_0_0_00 = 1001_0000 = 0x90.
        let d = decode(0x5E62_9020)
        #expect(d.mnemonic == .sqdmlal)
        // Accumulating ⇒ Rd reads itself.
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func sqdmlslScalarHToS() {
        // opcode=1011.
        let d = decode(0x5E62_B020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmullScalarHToS() {
        // opcode=1101.
        let d = decode(0x5E62_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmullScalarSToD() {
        // size=10 (S → D).
        let d = decode(0x5EA2_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func reservedSizeReturnsUndefined() {
        // size=00 reserved.
        let d = decode(0x5E22_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSize11ReturnsUndefined() {
        let d = decode(0x5EE2_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedUEqualsOneReturnsUndefined() {
        // U=1 not allowed at scalar three-different.
        let d = decode(0x7E62_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        // opcode=1000 reserved (no scalar three-different mnemonic).
        let d = decode(0x5E62_8020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar two-reg-misc — saturating zero compare,
/// SQABS/SQNEG/ABS/NEG, SQXTN/UQXTN/SQXTUN, plus FP family.
@Suite("SIMD/FP / AdvSIMD scalar two-reg-misc")
struct AdvSIMDScalarTwoRegMiscTests {
    @Test func sqabsDoubleScalar() {
        // SQABS D0, D1: U=0, size=11, opcode=00111.
        // byte 1: 11_1_0000_0 = 1110_0000 = 0xE0.
        // byte 2: 0111_10_00 = 0111_1000 = 0x78.
        let d = decode(0x5EE0_7820)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func sqnegDoubleScalar() {
        let d = decode(0x7EE0_7820)
        #expect(d.mnemonic == .sqneg)
    }

    @Test func absDoubleScalar() {
        // ABS: opcode=01011.
        let d = decode(0x5EE0_B820)
        #expect(d.mnemonic == .abs)
    }

    @Test func negDoubleScalar() {
        let d = decode(0x7EE0_B820)
        #expect(d.mnemonic == .neg)
    }

    @Test func cmgtZeroDoubleScalar() {
        // CMGT zero: opcode=01000.
        // byte 2: 1000_10_00 = 1000_1000 = 0x88.
        let d = decode(0x5EE0_8820)
        #expect(d.mnemonic == .cmgt)
        // Third operand is #0.
        #expect(d.operands.count == 3)
    }

    @Test func cmeqZeroDoubleScalar() {
        let d = decode(0x5EE0_9820)
        #expect(d.mnemonic == .cmeq)
    }

    @Test func cmltZeroDoubleScalar() {
        let d = decode(0x5EE0_A820)
        #expect(d.mnemonic == .cmlt)
    }

    @Test func cmgeZeroDoubleScalar() {
        let d = decode(0x7EE0_8820)
        #expect(d.mnemonic == .cmge)
    }

    @Test func cmleZeroDoubleScalar() {
        let d = decode(0x7EE0_9820)
        #expect(d.mnemonic == .cmle)
    }

    @Test func suqaddScalar() {
        // SUQADD: opcode=00011.
        let d = decode(0x5EE0_3820)
        #expect(d.mnemonic == .suqadd)
    }

    @Test func usqaddScalar() {
        let d = decode(0x7EE0_3820)
        #expect(d.mnemonic == .usqadd)
    }

    @Test func sqxtnByteScalar() {
        // SQXTN B0, H1: U=0, size=00, opcode=10100.
        // byte 1: 00_1_0000_1 = 0x21. byte 2: 0100_10_00 = 0x48.
        let d = decode(0x5E21_4820)
        #expect(d.mnemonic == .sqxtn)
    }

    @Test func uqxtnByteScalar() {
        let d = decode(0x7E21_4820)
        #expect(d.mnemonic == .uqxtn)
    }

    @Test func sqxtunByteScalar() {
        // SQXTUN: U=1, opcode=10010.
        // byte 2: 0010_10_00 = 0010_1000 = 0x28.
        let d = decode(0x7E21_2820)
        #expect(d.mnemonic == .sqxtun)
    }

    /// FP family.
    @Test func fcvtnsScalarSingle() {
        // FCVTNS S0, S1: U=0, opcode=11010, altBit=0 (size=00 ⇒ sz=0).
        // byte 1: 00_1_0000_1 = 0x21. byte 2: 1010_10_00 = 1010_1000 = 0xA8.
        let d = decode(0x5E21_A820)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcvtpsScalarSingle() {
        // altBit=1 (size=10 ⇒ bit 23=1, sz=0).
        let d = decode(0x5EA1_A820)
        #expect(d.mnemonic == .fcvtps)
    }

    @Test func fcvtmsScalarSingle() {
        let d = decode(0x5E21_B820)
        #expect(d.mnemonic == .fcvtms)
    }

    @Test func fcvtzsScalarSingle() {
        let d = decode(0x5EA1_B820)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtasScalarSingle() {
        // opcode=11100.
        let d = decode(0x5E21_C820)
        #expect(d.mnemonic == .fcvtas)
    }

    @Test func scvtfScalarSingle() {
        // opcode=11101.
        let d = decode(0x5E21_D820)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func frecpeScalarSingle() {
        // FRECPE per ARM ARM: opcode=11101, altBit=1 (size=10).
        let d = decode(0x5EA1_D820)
        #expect(d.mnemonic == .frecpe)
    }

    @Test func frecpxScalarSingle() {
        // FRECPX per ARM ARM: opcode=11111, altBit=1.
        let d = decode(0x5EA1_F820)
        #expect(d.mnemonic == .frecpx)
    }

    @Test func fsqrtScalarSingle() {
        // FSQRT S0, S1: scalar FSQRT is FP data-processing (1-source),
        // ftype=00 opcode=000011 — not AdvSIMD scalar two-reg-misc (which
        // has no FSQRT). Encoding 0x1E21_C020.
        let d = decode(0x1E21_C020)
        #expect(d.mnemonic == .fsqrt)
    }

    @Test func fcvtnuScalarSingle() {
        let d = decode(0x7E21_A820)
        #expect(d.mnemonic == .fcvtnu)
    }

    @Test func fcvtpuScalarSingle() {
        let d = decode(0x7EA1_A820)
        #expect(d.mnemonic == .fcvtpu)
    }

    @Test func fcvtmuScalarSingle() {
        let d = decode(0x7E21_B820)
        #expect(d.mnemonic == .fcvtmu)
    }

    @Test func fcvtzuScalarSingle() {
        let d = decode(0x7EA1_B820)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func fcvtauScalarSingle() {
        let d = decode(0x7E21_C820)
        #expect(d.mnemonic == .fcvtau)
    }

    @Test func ucvtfScalarSingle() {
        let d = decode(0x7E21_D820)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func frsqrteScalarSingle() {
        // FRSQRTE per ARM ARM: U=1, opcode=11101, altBit=1.
        let d = decode(0x7EA1_D820)
        #expect(d.mnemonic == .frsqrte)
    }

    @Test func fcmgtZeroScalarSingle() {
        // FCMGT 0: opcode=01100, altBit=1 (bit 23 = 1 for FP-family marker).
        let d = decode(0x5EA0_C820)
        #expect(d.mnemonic == .fcmgt)
    }

    @Test func fcmeqZeroScalarSingle() {
        let d = decode(0x5EA0_D820)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func fcmltZeroScalarSingle() {
        let d = decode(0x5EA0_E820)
        #expect(d.mnemonic == .fcmlt)
    }

    @Test func fcmgeZeroScalarSingle() {
        let d = decode(0x7EA0_C820)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmleZeroScalarSingle() {
        let d = decode(0x7EA0_D820)
        #expect(d.mnemonic == .fcmle)
    }

    @Test func reservedIntScalarTwoRegMiscReturnsUndefined() {
        // U=0 opcode=00000 reserved (no scalar mapping).
        let d = decode(0x5EE0_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFPScalarTwoRegMiscReturnsUndefined() {
        // U=0 opcode=11100 altBit=1 — no scalar two-reg-misc FP case.
        let d = decode(0x5EA1_C820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar pairwise — ADDP (D), FMAXNMP/FMINNMP/FADDP/
/// FMAXP/FMINP (S, D FP forms).
@Suite("SIMD/FP / AdvSIMD scalar pairwise")
struct AdvSIMDScalarPairwiseTests {
    @Test func addpScalarDoublePair() {
        // ADDP D0, V1.2D: U=0, size=11, opcode=11011.
        // Scalar pairwise fixes bits[21:17] = 11000: bit 21 = 1, bits[20:17] = 1000.
        // byte 1: size(2)+1+1000+opcode[4] = 11_1_1000_X.
        // opcode = 11011 → bit 16 = 1 (high bit of opcode).
        // byte 1 = 11_1_1000_1 = 1111_0001 = 0xF1.
        // byte 2: opcode[3:0] (4 bits) + 10 (bits[11:10]) + Rn high (2 bits).
        // opcode[3:0] = 1011. bits 11..10 = 10. Rn=1 ⇒ bits 9..8 = 00.
        // byte 2 = 1011_10_00 = 1011_1000 = 0xB8.
        let d = decode(0x5EF1_B820)
        #expect(d.mnemonic == .addp)
    }

    @Test func reservedAddpNonDoubleSizeReturnsUndefined() {
        // ADDP scalar requires size=11 (.2D). Use size=10 (S) — invalid for
        // ADDP scalar.
        let d = decode(0x5EB1_B820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmaxnmpScalarSinglePair() {
        // FMAXNMP S0, V1.2S: U=1, opcode=01100, altBit=0 (size=00).
        // byte 1: 00_1_1000_0 = 0011_0000 = 0x30. byte 2: 1100_10_00 = 1100_1000 = 0xC8.
        let d = decode(0x7E30_C820)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpScalarSinglePair() {
        // altBit=1 (size=10).
        let d = decode(0x7EB0_C820)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func faddpScalarSinglePair() {
        // FADDP: U=1, opcode=01101, altBit=0.
        let d = decode(0x7E30_D820)
        #expect(d.mnemonic == .faddp)
    }

    @Test func fmaxpScalarSinglePair() {
        // FMAXP: U=1, opcode=01111, altBit=0.
        let d = decode(0x7E30_F820)
        #expect(d.mnemonic == .fmaxp)
    }

    @Test func fminpScalarSinglePair() {
        // FMINP: U=1, opcode=01111, altBit=1.
        let d = decode(0x7EB0_F820)
        #expect(d.mnemonic == .fminp)
    }

    @Test func reservedScalarPairwiseReturnsUndefined() {
        // U=1 opcode=01000 reserved.
        let d = decode(0x7E30_8820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func uEqualsZeroNonAddpReturnsUndefined() {
        // U=0 opcode != 11011 reserved.
        let d = decode(0x5EF1_C820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar copy — DUP element scalar (aliased to MOV).
@Suite("SIMD/FP / AdvSIMD scalar copy")
struct AdvSIMDScalarCopyTests {
    @Test func dupElementScalarByte() {
        // DUP (element, scalar), alias MOV. The scalar copy row lives in
        // the SCALAR tier: top byte 0x5E/0x7E (bit 28 = 1, unlike the
        // vector copy shell 0x0E/0x4E at bit 28 = 0), bit 21 = 0, with
        // op = 0 and imm4 = 0000 the only allocated arm. imm5 = 00001
        // selects element size B, index 0; Rn = 1, Rd = 0.
        // 0x5E01_0420 decodes `mov b0, v1.b[0]` (llvm-mc agrees); the
        // same payload under the vector shell, 0x4E01_0420, renders
        // `dup v0.16b, v1.b[0]` — the two tiers are routed by bit 28.
        let d = decode(0x5E01_0420)
        #expect(d.mnemonic == .mov) // DUP scalar aliases to MOV.
    }

    @Test func dupElementScalarHalfword() {
        // imm5 = 00010 (halfword, index=0). byte 1: 00_0_00010 = 0x02.
        let d = decode(0x5E02_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementScalarWord() {
        // imm5 = 00100 (word, index=0).
        let d = decode(0x5E04_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementScalarDoubleword() {
        // imm5 = 01000 (doubleword, index=0).
        let d = decode(0x5E08_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func reservedImm5ZeroReturnsUndefined() {
        // imm5 = 00000 reserved.
        let d = decode(0x5E00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpEqualsOneReturnsUndefined() {
        // op=1 (INS element-to-element) not handled at scalar copy.
        let d = decode(0x7E01_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedImm4NonZeroReturnsUndefined() {
        // imm4 != 0000 reserved at scalar copy.
        // imm4 bit at byte 2 bit 11 = 1 ⇒ byte 2 = 0000_1100 = 0x0C.
        let d = decode(0x5E01_0C20)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar shift-by-immediate — SHL/SSHR/SSRA/SRSHR/SRSRA
/// USHR/USRA/URSHR/URSRA/SRI/SLI/SQSHL/SQSHRN/SQRSHRN/SQSHRUN/SQRSHRUN/
/// SQSHLU/UQSHRN/UQRSHRN/SCVTF/UCVTF/FCVTZS/FCVTZU at scalar widths.
@Suite("SIMD/FP / AdvSIMD scalar shift-by-immediate")
struct AdvSIMDScalarShiftByImmediateTests {
    @Test func sshrScalarDouble() {
        // SSHR D0, D1, #1: U=0.
        // For shift=1 with D-element (elementBits=64):
        // shift = (2 * 64) - immhb ⇒ immhb = 128 - 1 = 127 = 0b1111111.
        // immh = bits[22:19] = 1111. immb = bits[18:16] = 111.
        // immh has high bit 1 → D-element. ✓
        // byte 1: 0_immh(4)_immb(3) = 0_1111_111 = 0111_1111 = 0x7F.
        // top byte = 0x5F.
        // byte 2: opcode(5) + bit10(1) + Rn high(2). opcode=00000, bit10=1.
        // byte 2 = 00000_1_00 = 0000_0100 = 0x04.
        let d = decode(0x5F7F_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func ssraScalarDouble() {
        // opcode=00010.
        let d = decode(0x5F7F_1420)
        #expect(d.mnemonic == .ssra)
    }

    @Test func srshrScalarDouble() {
        let d = decode(0x5F7F_2420)
        #expect(d.mnemonic == .srshr)
    }

    @Test func srsraScalarDouble() {
        let d = decode(0x5F7F_3420)
        #expect(d.mnemonic == .srsra)
    }

    @Test func shlScalarDouble() {
        // SHL D0, D1, #1: U=0, opcode=01010, immhb = 64 + 1 = 65 = 0b1000001.
        // immh = 1000, immb = 001. byte 1 = 0_1000_001 = 0100_0001 = 0x41.
        // byte 2: 01010_1_00 = 0101_0100 = 0x54.
        let d = decode(0x5F41_5420)
        #expect(d.mnemonic == .shl)
    }

    @Test func sqshlScalarDouble() {
        // opcode=01110.
        let d = decode(0x5F41_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func sqshrnScalarHalf() {
        // SQSHRN S0, D1, #1: U=0, opcode=10010. Shift-immediate narrowing:
        // immh's highest set bit selects the destination element
        // (immh = 01xx → S, narrowing from D), and shift = (2 × 32) − immhb.
        // For shift 1: immhb = 0111_111 = 63; immh = 0111, immb = 111.
        // byte 1 (bit 23 = 0, immh at bits[22:19], immb at bits[18:16]):
        // 0_0111_111 = 0011_1111 = 0x3F.
        // byte 2: opcode 10010 + bit 10 = 1 + Rn high bits = 1001_0100 = 0x94.
        // Decodes `sqshrn s0, d1, #1` (llvm-mc agrees).
        let d = decode(0x5F3F_9420)
        #expect(d.mnemonic == .sqshrn)
    }

    @Test func sqrshrnScalarHalf() {
        // opcode=10011.
        let d = decode(0x5F3F_9C20)
        #expect(d.mnemonic == .sqrshrn)
    }

    @Test func scvtfScalarFixed() {
        // SCVTF S0, S1, #1: U=0, opcode=11100.
        // byte 2: 11100_1_00 = 1110_0100 = 0xE4.
        let d = decode(0x5F3F_E420)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func fcvtzsScalarFixed() {
        // opcode=11111.
        let d = decode(0x5F3F_FC20)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func ushrScalarDouble() {
        // U=1, opcode=00000.
        let d = decode(0x7F7F_0420)
        #expect(d.mnemonic == .ushr)
    }

    @Test func usraScalarDouble() {
        let d = decode(0x7F7F_1420)
        #expect(d.mnemonic == .usra)
    }

    @Test func urshrScalarDouble() {
        let d = decode(0x7F7F_2420)
        #expect(d.mnemonic == .urshr)
    }

    @Test func ursraScalarDouble() {
        let d = decode(0x7F7F_3420)
        #expect(d.mnemonic == .ursra)
    }

    @Test func sriScalarDouble() {
        let d = decode(0x7F7F_4420)
        #expect(d.mnemonic == .sri)
    }

    @Test func sliScalarDouble() {
        let d = decode(0x7F41_5420)
        #expect(d.mnemonic == .sli)
    }

    @Test func sqshluScalarDouble() {
        let d = decode(0x7F41_6420)
        #expect(d.mnemonic == .sqshlu)
    }

    @Test func uqshlScalarDouble() {
        let d = decode(0x7F41_7420)
        #expect(d.mnemonic == .uqshl)
    }

    @Test func sqshrunScalarHalf() {
        let d = decode(0x7F3F_8420)
        #expect(d.mnemonic == .sqshrun)
    }

    @Test func sqrshrunScalarHalf() {
        let d = decode(0x7F3F_8C20)
        #expect(d.mnemonic == .sqrshrun)
    }

    @Test func uqshrnScalarHalf() {
        let d = decode(0x7F3F_9420)
        #expect(d.mnemonic == .uqshrn)
    }

    @Test func uqrshrnScalarHalf() {
        let d = decode(0x7F3F_9C20)
        #expect(d.mnemonic == .uqrshrn)
    }

    @Test func ucvtfScalarFixed() {
        let d = decode(0x7F3F_E420)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fcvtzuScalarFixed() {
        let d = decode(0x7F3F_FC20)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func immhEqualsZeroReturnsUndefined() {
        // immh=0000 reserved.
        let d = decode(0x5F00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        // U=0 opcode=11000 reserved (no scalar shift mapping).
        let d = decode(0x5F7F_C420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dOnlyOpcodeWithNonDElementReturnsUndefined() {
        // SSHR (D-only) with B-element ⇒ reserved.
        // immh = 0001 (B). U=0 opcode=00000.
        let d = decode(0x5F0F_0420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar x-indexed-element — SQDMLAL/SQDMLSL/SQDMULL
/// SQDMULH/SQRDMULH/FMLA/FMLS/FMUL/FMULX/SQRDMLAH/SQRDMLSH.
@Suite("SIMD/FP / AdvSIMD scalar x-indexed-element")
struct AdvSIMDScalarXIndexedElementTests {
    @Test func fmulScalarSingleElement() {
        // FMUL S0, S1, V2.S[0]: U=0, sz=0, opcode=1001, L=0, M=0, H=0, Rm=2.
        // Pattern: `0 1 U 1 1111 size L M Rm opcode H 0 Rn Rd`.
        // top byte 0x5F. byte 1: size=00, L=0, M=0, Rm[3:0]=0010 ⇒ 00_0_0_0010 = 0x02.
        // byte 2: opcode=1001, H=0, bit 10 = 0, Rn[4:3] = 00.
        // byte 2 = 1001_0_0_00 = 1001_0000 = 0x90.
        let d = decode(0x5F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmlaScalarSingleElement() {
        // opcode=0001.
        let d = decode(0x5F82_1020)
        #expect(d.mnemonic == .fmla)
    }

    @Test func fmlsScalarSingleElement() {
        let d = decode(0x5F82_5020)
        #expect(d.mnemonic == .fmls)
    }

    @Test func fmulxScalarSingleElement() {
        // U=1, opcode=1001.
        let d = decode(0x7F82_9020)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func sqdmlalScalarHToS() {
        // SQDMLAL S0, H1, V2.H[0]: size=01 (H source, S dest), opcode=0011.
        // byte 1: 01_0_0_0010 = 0100_0010 = 0x42. byte 2: 0011_0_0_00 = 0011_0000 = 0x30.
        let d = decode(0x5F42_3020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func sqdmlslScalarHToS() {
        // opcode=0111.
        let d = decode(0x5F42_7020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmullScalarHToS() {
        // opcode=1011.
        let d = decode(0x5F42_B020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmulhScalarHalf() {
        // opcode=1100, U=0.
        let d = decode(0x5F42_C020)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhScalarHalf() {
        let d = decode(0x5F42_D020)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func sqrdmlahScalarHalf() {
        // U=1, opcode=1101.
        let d = decode(0x7F42_D020)
        #expect(d.mnemonic == .sqrdmlah)
    }

    @Test func sqrdmlshScalarHalf() {
        // U=1, opcode=1111.
        let d = decode(0x7F42_F020)
        #expect(d.mnemonic == .sqrdmlsh)
    }

    @Test func reservedFPOpcodeReturnsUndefined() {
        // U=1 opcode=0001 (FMLA isn't U=1).
        let d = decode(0x7F82_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntSizeReturnsUndefined() {
        // size=00 reserved for int family.
        let d = decode(0x5F02_3020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        // size=01, U=0 opcode=0000 reserved.
        let d = decode(0x5F42_0020)
        #expect(d.mnemonic == .undefined)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD vector copy — DUP element / DUP general / SMOV / UMOV
/// / INS element-to-element / INS general (aliased to MOV).
@Suite("SIMD/FP / AdvSIMD vector copy")
struct AdvSIMDVectorCopyTests {
    @Test func dupElementToVectorB8() {
        // DUP V0.8B, V1.B[0]: Q=0, op=0, imm5=00001, imm4=0000.
        // top byte 0x0E. byte 1: 00_0_00001 = 0x01. byte 2: 0000_0_1_00 = 0x04.
        let d = decode(0x0E01_0420)
        #expect(d.mnemonic == .dup)
        // Destination .b8.
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func dupElementToVectorB16() {
        // Q=1.
        let d = decode(0x4E01_0420)
        #expect(d.mnemonic == .dup)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b16)),
        ))
    }

    @Test func dupElementToVectorH4() {
        // imm5=00010 (H, index=0). byte 1 = 0000_0010 = 0x02.
        let d = decode(0x0E02_0420)
        #expect(d.mnemonic == .dup)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h4)),
        ))
    }

    @Test func dupElementToVectorS2() {
        // imm5=00100 (S, index=0).
        let d = decode(0x0E04_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementToVectorD2() {
        // imm5=01000 (D, index=0). Q=1 (D only valid at Q=1).
        let d = decode(0x4E08_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementDqWithQZeroReservedDLane() {
        // DUP V0.1D ⇒ Q=0 with D-element is reserved: arrangementFor
        // returns nil for (.d, Q=0), so the decode is undefined.
        let d = decode(0x0E08_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dupGeneralWFromWByteVector() {
        // DUP V0.8B, W1: op=0, imm4=0001. byte 2 = 0000_1_1_00 = 0x0C.
        let d = decode(0x0E01_0C20)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupGeneralXFromXDoubleword() {
        // DUP V0.2D, X1: op=0, imm4=0001, imm5=01000 (D), Q=1.
        // byte 1: 00_0_01000 = 0x08.
        let d = decode(0x4E08_0C20)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupGeneralDWithQZeroReserved() {
        // D-element with Q=0 reserved.
        let d = decode(0x0E08_0C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func insGeneralAliasMov() {
        // INS V0.B[0], W1: op=0, imm4=0011, Q=1 required.
        // byte 2 = 0001_1_1_00 = 0x1C.
        let d = decode(0x4E01_1C20)
        #expect(d.mnemonic == .mov)
        // Destination is element view.
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .element(arrangement: .b16, index: 0)),
        ))
    }

    @Test func insGeneralQZeroReserved() {
        let d = decode(0x0E01_1C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smovWFromVnB() {
        // SMOV W0, V1.B[0]: op=0, imm4=0101, Q=0 (W destination).
        // byte 2: 0010_1_1_00 = 0010_1100 = 0x2C.
        let d = decode(0x0E01_2C20)
        #expect(d.mnemonic == .smov)
    }

    @Test func smovXFromVnB() {
        // Q=1 ⇒ Xd.
        let d = decode(0x4E01_2C20)
        #expect(d.mnemonic == .smov)
    }

    @Test func smovDLaneReserved() {
        // SMOV with D-element reserved.
        let d = decode(0x4E08_2C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smovSElementQZeroReserved() {
        // SMOV with S-element requires Q=1.
        let d = decode(0x0E04_2C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func umovWFromVnB() {
        // UMOV W0, V1.B[0]: imm4=0111, Q=0.
        // byte 2: 0011_1_1_00 = 0011_1100 = 0x3C.
        let d = decode(0x0E01_3C20)
        #expect(d.mnemonic == .umov)
    }

    @Test func umovWFromVnS_AliasMov() {
        // UMOV W0, V1.S[0] aliases to MOV.
        let d = decode(0x0E04_3C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovXFromVnD_AliasMov() {
        // UMOV X0, V1.D[0] aliases to MOV.
        let d = decode(0x4E08_3C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovBHWithQOneReserved() {
        // UMOV W from B/H requires Q=0; Q=1 reserved.
        let d = decode(0x4E01_3C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func insElementToElementAliasMov() {
        // INS V0.B[0], V1.B[0]: op=1, imm5=00001, imm4=any.
        // Top byte 0x6E (op=1 ⇒ bit 29 = 1, Q=1 required).
        let d = decode(0x6E01_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementToElementQZeroReserved() {
        // op=1 with Q=0 reserved.
        let d = decode(0x2E01_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func imm5ZeroReservedAtVectorCopy() {
        let d = decode(0x0E00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownImm4ReturnsUndefined() {
        // imm4=0100 not defined.
        // byte 2: 0010_0_1_00 = 0010_0100 = 0x24.
        let d = decode(0x0E01_2420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector permute — UZP1/UZP2/TRN1/TRN2/ZIP1/ZIP2.
@Suite("SIMD/FP / AdvSIMD vector permute")
struct AdvSIMDVectorPermuteTests {
    @Test func uzp1V0_8B() {
        // UZP1 V0.8B, V1.8B, V2.8B: Q=0, size=00, opcode=001.
        // Pattern `0 Q 00 1110 size 0 Rm 0 opcode 1 0 Rn Rd`.
        // top byte 0x0E. byte 1: size 00, bit 21 = 0, bits 20..16 = Rm = 00010.
        // = 00_0_00010 = 0x02.
        // byte 2: bit 15 = 0, bits 14..12 = opcode = 001, bit 11 = 1, bit 10 = 0.
        // = 0_001_1_0_00 (with bits 9..8 = 00 for Rn=1) = 0001_1000 = 0x18.
        let d = decode(0x0E02_1820)
        #expect(d.mnemonic == .uzp1)
    }

    @Test func trn1V0_8B() {
        // opcode=010. byte 2: 0_010_1_0_00 = 0010_1000 = 0x28.
        let d = decode(0x0E02_2820)
        #expect(d.mnemonic == .trn1)
    }

    @Test func zip1V0_8B() {
        // opcode=011.
        let d = decode(0x0E02_3820)
        #expect(d.mnemonic == .zip1)
    }

    @Test func uzp2V0_8B() {
        // opcode=101.
        let d = decode(0x0E02_5820)
        #expect(d.mnemonic == .uzp2)
    }

    @Test func trn2V0_8B() {
        let d = decode(0x0E02_6820)
        #expect(d.mnemonic == .trn2)
    }

    @Test func zip2V0_8B() {
        let d = decode(0x0E02_7820)
        #expect(d.mnemonic == .zip2)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        // opcode=000 reserved.
        let d = decode(0x0E02_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSizeD1ReturnsUndefined() {
        // size=11 Q=0 (.1D) reserved.
        let d = decode(0x0EE2_1820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector extract — EXT.
@Suite("SIMD/FP / AdvSIMD vector extract")
struct AdvSIMDVectorExtractTests {
    @Test func extV0_8B() {
        // EXT V0.8B, V1.8B, V2.8B, #1: Q=0, op2=00, imm4=0001.
        // bits[29:28]=10, bit 24=0. top byte 0010_1110 = 0x2E.
        // byte 1: 00_0_00010 = 0x02. byte 2: 0_0001_0_00 = 0x08.
        let d = decode(0x2E02_0820)
        #expect(d.mnemonic == .ext)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func extV0_16B() {
        // Q=1.
        let d = decode(0x6E02_0820)
        #expect(d.mnemonic == .ext)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b16)),
        ))
    }

    @Test func extQZeroImm4HighBitReserved() {
        // Q=0 with imm4[3]=1 reserved.
        let d = decode(0x2E02_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func extOp2NonZeroReserved() {
        // op2 != 00 reserved.
        let d = decode(0x2E62_0820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD table lookup — TBL/TBX.
@Suite("SIMD/FP / AdvSIMD table lookup")
struct AdvSIMDTableLookupTests {
    @Test func tblOneTableV0_8B() {
        // TBL V0.8B, {V1.16B}, V2.8B: Q=0, len=00, op=0.
        // top byte 0x0E. byte 1: 00_0_00010 = 0x02.
        // byte 2: 0_00_0_0_0_00 = 0x00. byte 3 = 0x20.
        let d = decode(0x0E02_0020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func tblTwoTablesV0_8B() {
        // len=01. byte 2: 0_01_0_0_0_00 = 0010_0000 = 0x20.
        let d = decode(0x0E02_2020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func tblThreeTablesV0_8B() {
        let d = decode(0x0E02_4020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func tblFourTablesV0_8B() {
        let d = decode(0x0E02_6020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func tbxOneTableV0_8B() {
        // op=1. byte 2: 0_00_1_0_0_00 = 0001_0000 = 0x10.
        let d = decode(0x0E02_1020)
        #expect(d.mnemonic == .tbx)
        // TBX reads destination.
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func tblQ1V0_16B() {
        let d = decode(0x4E02_0020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func reservedOp2ReturnsUndefined() {
        // op2 != 00 reserved.
        let d = decode(0x0E42_0020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD across-lanes — ADDV, SADDLV, UADDLV, SMAXV, SMINV,
/// UMAXV, UMINV, FMAXNMV, FMAXV, FMINNMV, FMINV.
@Suite("SIMD/FP / AdvSIMD across-lanes")
struct AdvSIMDAcrossLanesTests {
    @Test func saddlvHFromV_8B() {
        // SADDLV H0, V1.8B: U=0, opcode=00011, size=00.
        // byte 1: 00_1_1000_0 = 0x30. byte 2: 0011_10_00 = 0x38.
        let d = decode(0x0E30_3820)
        #expect(d.mnemonic == .saddlv)
    }

    @Test func uaddlvFrom_8B() {
        let d = decode(0x2E30_3820)
        #expect(d.mnemonic == .uaddlv)
    }

    @Test func smaxvHFromV_8B() {
        // opcode=01010.
        let d = decode(0x0E30_A820)
        #expect(d.mnemonic == .smaxv)
    }

    @Test func sminvHFromV_8B() {
        // opcode=11010.
        let d = decode(0x0E31_A820)
        #expect(d.mnemonic == .sminv)
    }

    @Test func addvFromV_8B() {
        // opcode=11011.
        let d = decode(0x0E31_B820)
        #expect(d.mnemonic == .addv)
    }

    @Test func umaxvHFromV_8B() {
        let d = decode(0x2E30_A820)
        #expect(d.mnemonic == .umaxv)
    }

    @Test func uminvHFromV_8B() {
        let d = decode(0x2E31_A820)
        #expect(d.mnemonic == .uminv)
    }

    @Test func fmaxnmvSFromV_4S() {
        // FMAXNMV: U=1, opcode=01100, Q=1, size=00 (sz=0).
        let d = decode(0x6E30_C820)
        #expect(d.mnemonic == .fmaxnmv)
    }

    @Test func fmaxvSFromV_4S() {
        // opcode=01111.
        let d = decode(0x6E30_F820)
        #expect(d.mnemonic == .fmaxv)
    }

    @Test func fminnmvSFromV_4S() {
        // FMINNMV S0, V1.4S: U=1, opcode=01100, Q=1, sz=1 (size=10).
        let d = decode(0x6EB0_C820)
        #expect(d.mnemonic == .fminnmv)
    }

    @Test func fminvSFromV_4S() {
        // FMINV S0, V1.4S: opcode=01111, sz=1.
        let d = decode(0x6EB0_F820)
        #expect(d.mnemonic == .fminv)
    }

    @Test func reservedAcrossLanesArrangement_1DReturnsUndefined() {
        // .1D arrangement (size=11, Q=0) reserved.
        let d = decode(0x0EF0_3820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAcrossLanesArrangement_2SReturnsUndefined() {
        // .2S (size=10, Q=0) reserved per ARM ARM.
        let d = decode(0x0EB0_3820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAcrossLanesOpcodeReturnsUndefined() {
        // U=0 opcode=00001 has no across-lanes mapping; reserved.
        let d = decode(0x0E30_0820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD modified-immediate — MOVI/MVNI/ORR-imm/BIC-imm/FMOV-imm
/// with various cmode/op combinations.
@Suite("SIMD/FP / AdvSIMD modified-immediate")
struct AdvSIMDModifiedImmediateTests {
    @Test func moviTwoEs() {
        // MOVI V0.2S, #0: Q=0, op=0, cmode=0000, abc=0, defgh=0.
        // top byte 0x0F. bits[23:19]=00000 means immediate class.
        let d = decode(0x0F00_0400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviFourS() {
        // Q=1.
        let d = decode(0x4F00_0400)
        #expect(d.mnemonic == .movi)
    }

    @Test func mvniTwoS() {
        // op=1, cmode=0000.
        let d = decode(0x2F00_0400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func orrImmTwoS() {
        // cmode=0001.
        let d = decode(0x0F00_1400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImmTwoS() {
        // cmode=0001, op=1.
        let d = decode(0x2F00_1400)
        #expect(d.mnemonic == .bic)
    }

    @Test func moviFourH() {
        // cmode=1000 (16-bit MOVI).
        let d = decode(0x0F00_8400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviEightH() {
        // Q=1 cmode=1000.
        let d = decode(0x4F00_8400)
        #expect(d.mnemonic == .movi)
    }

    @Test func orrImm_4H() {
        // cmode=1001.
        let d = decode(0x0F00_9400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImm_4H() {
        let d = decode(0x2F00_9400)
        #expect(d.mnemonic == .bic)
    }

    @Test func moviMSLShift8() {
        // cmode=1100.
        let d = decode(0x0F00_C400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviMSLShift16() {
        // cmode=1101.
        let d = decode(0x0F00_D400)
        #expect(d.mnemonic == .movi)
    }

    @Test func mvniMSLShift8() {
        // op=1, cmode=1100.
        let d = decode(0x2F00_C400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func moviEightBitByte() {
        // cmode=1110, op=0.
        let d = decode(0x0F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviSixtyFourBit() {
        // cmode=1110, op=1, Q=1.
        let d = decode(0x6F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviSixtyFourBitScalarDn() {
        // MOVI D0, #0: cmode=1110, op=1, Q=0 is the scalar 64-bit (Dn) form.
        let d = decode(0x2F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func fmovImmediateSingle() {
        // FMOV V0.2S, #X: cmode=1111, op=0.
        let d = decode(0x0F00_F400)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovImmediateDouble() {
        // cmode=1111, op=1, Q=1.
        let d = decode(0x6F00_F400)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovImmediateDoubleQZeroReserved() {
        // cmode=1111, op=1, Q=0 reserved.
        let d = decode(0x2F00_F400)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD shift-by-immediate — SSHR/SSRA/SRSHR/SRSRA/SHL/SQSHL/
/// SHRN/RSHRN/SQSHRN/SQRSHRN/SSHLL/SXTL/SXTL2/USHR/USRA/URSHR/URSRA/SRI/SLI/
/// SQSHLU/UQSHL/SQSHRUN/SQRSHRUN/UQSHRN/UQRSHRN/USHLL/UXTL/UXTL2/SCVTF
/// (fixed)/FCVTZS (fixed)/UCVTF (fixed)/FCVTZU (fixed).
@Suite("SIMD/FP / AdvSIMD shift-by-immediate")
struct AdvSIMDShiftByImmediateTests {
    @Test func sshrV0_8B() {
        // SSHR V0.8B, V1.8B, #1: Q=0, U=0, immh=0001, immb=111.
        // top byte 0x0F. byte 1: 0_0001_111 = 0000_1111 = 0x0F.
        // byte 2 (opcode at bits[15:11], bit 10 = 1, Rn-high = 00):
        // SSHR opcode=00000 → 00000_1_00 = 0000_0100 = 0x04.
        let d = decode(0x0F0F_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func ssra() {
        let d = decode(0x0F0F_1420)
        #expect(d.mnemonic == .ssra)
    }

    @Test func srshr() {
        let d = decode(0x0F0F_2420)
        #expect(d.mnemonic == .srshr)
    }

    @Test func srsra() {
        let d = decode(0x0F0F_3420)
        #expect(d.mnemonic == .srsra)
    }

    @Test func shl() {
        // SHL: opcode=01010.
        let d = decode(0x0F09_5420)
        #expect(d.mnemonic == .shl)
    }

    @Test func sqshl() {
        let d = decode(0x0F09_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func shrn_AndShrn2() {
        // SHRN V0.8B, V1.8H, #1: opcode=10000.
        let d = decode(0x0F0F_8420)
        #expect(d.mnemonic == .shrn)
        // Q=1 promotes to shrn2.
        let d2 = decode(0x4F0F_8420)
        #expect(d2.mnemonic == .shrn2)
    }

    @Test func rshrn() {
        let d = decode(0x0F0F_8C20)
        #expect(d.mnemonic == .rshrn)
        let d2 = decode(0x4F0F_8C20)
        #expect(d2.mnemonic == .rshrn2)
    }

    @Test func sqshrn() {
        let d = decode(0x0F0F_9420)
        #expect(d.mnemonic == .sqshrn)
        let d2 = decode(0x4F0F_9420)
        #expect(d2.mnemonic == .sqshrn2)
    }

    @Test func sqrshrn() {
        let d = decode(0x0F0F_9C20)
        #expect(d.mnemonic == .sqrshrn)
        let d2 = decode(0x4F0F_9C20)
        #expect(d2.mnemonic == .sqrshrn2)
    }

    @Test func sshllShiftZero() {
        // SSHLL V0.8H, V1.8B, #0: opcode=10100, shift=0 with immh=0001 (single bit).
        // The SXTL alias maps to this encoding, but the canonical decode is SSHLL #0
        // (matches llvm-mc).
        // immhb = elementBits + shift = 8 + 0 = 8 = 0b001000. immh = 0001, immb = 000.
        // byte 1 = 0_0001_000 = 0000_1000 = 0x08. byte 2: 10100_1_0_0 + 00 = 1010_0100 = 0xA4.
        let d = decode(0x0F08_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshllNonZeroShift() {
        // SSHLL V0.8H, V1.8B, #1: immhb = 8 + 1 = 9 = 0b001001. immh = 0001, immb = 001.
        // byte 1 = 0_0001_001 = 0000_1001 = 0x09.
        let d = decode(0x0F09_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshll2ShiftZeroQ1() {
        // Q=1 with shift=0: SXTL2 alias maps here, canonical decode is SSHLL2 #0.
        let d = decode(0x4F08_A420)
        #expect(d.mnemonic == .sshll2)
    }

    @Test func ushr() {
        let d = decode(0x2F0F_0420)
        #expect(d.mnemonic == .ushr)
    }

    @Test func usra() {
        let d = decode(0x2F0F_1420)
        #expect(d.mnemonic == .usra)
    }

    @Test func urshr() {
        let d = decode(0x2F0F_2420)
        #expect(d.mnemonic == .urshr)
    }

    @Test func ursra() {
        let d = decode(0x2F0F_3420)
        #expect(d.mnemonic == .ursra)
    }

    @Test func sri() {
        let d = decode(0x2F0F_4420)
        #expect(d.mnemonic == .sri)
    }

    @Test func sli() {
        let d = decode(0x2F09_5420)
        #expect(d.mnemonic == .sli)
    }

    @Test func sqshlu() {
        let d = decode(0x2F09_6420)
        #expect(d.mnemonic == .sqshlu)
    }

    @Test func uqshl() {
        let d = decode(0x2F09_7420)
        #expect(d.mnemonic == .uqshl)
    }

    @Test func sqshrun() {
        let d = decode(0x2F0F_8420)
        #expect(d.mnemonic == .sqshrun)
        let d2 = decode(0x6F0F_8420)
        #expect(d2.mnemonic == .sqshrun2)
    }

    @Test func sqrshrun() {
        let d = decode(0x2F0F_8C20)
        #expect(d.mnemonic == .sqrshrun)
    }

    @Test func uqshrn() {
        let d = decode(0x2F0F_9420)
        #expect(d.mnemonic == .uqshrn)
    }

    @Test func uqrshrn() {
        let d = decode(0x2F0F_9C20)
        #expect(d.mnemonic == .uqrshrn)
    }

    @Test func ushllShiftZero() {
        // USHLL with shift=0: UXTL alias maps here, canonical decode is USHLL #0.
        let d = decode(0x2F08_A420)
        #expect(d.mnemonic == .ushll)
    }

    @Test func ushllNonZeroShift() {
        let d = decode(0x2F09_A420)
        #expect(d.mnemonic == .ushll)
    }

    @Test func ushll2ShiftZeroQ1() {
        // Q=1 with shift=0: UXTL2 alias maps here, canonical decode is USHLL2 #0.
        let d = decode(0x6F08_A420)
        #expect(d.mnemonic == .ushll2)
    }

    @Test func scvtfFixedVector() {
        let d = decode(0x0F2F_E420)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func ucvtfFixedVector() {
        let d = decode(0x2F2F_E420)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func fcvtzsFixedVector() {
        let d = decode(0x0F2F_FC20)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtzuFixedVector() {
        let d = decode(0x2F2F_FC20)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func immhZeroReturnsUndefined() {
        // To reach AdvSIMDShiftByImmediateDecode (not modified-immediate),
        // bits[23:19] must be non-zero. Set bit 23 = 1 with immh = 0000.
        // byte 1 = 1000_0000 = 0x80.
        let d = decode(0x0F80_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dElementWithQ0NonLengtheningReturnsUndefined() {
        // SSHR with immh=1000 (D-element), Q=0 reserved.
        let d = decode(0x0F7F_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        // U=0 opcode=01100 reserved.
        let d = decode(0x0F0F_6420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector x-indexed-element — FMLA/FMLS/FMUL/FMULX/SMLAL/
/// SMLSL/SMULL/SQDMULL/SQDMLAL/SQDMLSL/MUL/MLA/MLS/SQDMULH/SQRDMULH/SDOT/
/// UMLAL/UMLSL/UMULL/UDOT.
@Suite("SIMD/FP / AdvSIMD vector x-indexed-element")
struct AdvSIMDVectorXIndexedElementTests {
    @Test func fmulVector_2S() {
        // FMUL V0.2S, V1.2S, V2.S[0]: Q=0, U=0, sz=0, L=0, M=0, H=0, Rm=2, opcode=1001.
        // top byte 0x0F. byte 1: 00_0_0_0010 = 0x02. byte 2: 1001_0_0_00 = 0x90.
        let d = decode(0x0F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmulVector_4S() {
        let d = decode(0x4F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmulVector_2D() {
        // sz=1, Q=1 (size=10 with bit 22 = 1).
        let d = decode(0x4FC2_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmlaVector_2S() {
        // opcode=0001.
        let d = decode(0x0F82_1020)
        #expect(d.mnemonic == .fmla)
    }

    @Test func fmlsVector_2S() {
        let d = decode(0x0F82_5020)
        #expect(d.mnemonic == .fmls)
    }

    @Test func fmulxVector_2S() {
        let d = decode(0x2F82_9020)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func mulVector_4H() {
        // MUL V0.4H, V1.4H, V2.H[0]: U=0, size=01, opcode=1000.
        // byte 1: 01_0_0_0010 = 0x42. byte 2: 1000_0_0_00 = 0x80.
        let d = decode(0x0F42_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func mlaVector_4H() {
        // MLA V0.4H, V1.4H, V2.H[0]: U=1, size=01, opcode=0000.
        let d = decode(0x2F42_0020)
        #expect(d.mnemonic == .mla)
    }

    @Test func mlsVector_4H() {
        // MLS V0.4H, V1.4H, V2.H[0]: U=1, size=01, opcode=0100.
        let d = decode(0x2F42_4020)
        #expect(d.mnemonic == .mls)
    }

    @Test func smlalVector_4S() {
        // SMLAL V0.4S, V1.4H, V2.H[0]: opcode=0010.
        let d = decode(0x0F42_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func smlslVector_4S() {
        let d = decode(0x0F42_6020)
        #expect(d.mnemonic == .smlsl)
    }

    @Test func smullVector_4S() {
        // opcode=1010.
        let d = decode(0x0F42_A020)
        #expect(d.mnemonic == .smull)
    }

    @Test func sqdmullVector_4S() {
        // opcode=1011.
        let d = decode(0x0F42_B020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmlalVector_4S() {
        // opcode=0011.
        let d = decode(0x0F42_3020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func sqdmlslVector_4S() {
        let d = decode(0x0F42_7020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmulhVector_4H() {
        // opcode=1100.
        let d = decode(0x0F42_C020)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhVector_4H() {
        let d = decode(0x0F42_D020)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func sdotVector_2S() {
        // SDOT V0.2S, V1.8B, V2.4B[0]: U=0, opcode=1110.
        let d = decode(0x0F82_E020)
        #expect(d.mnemonic == .sdot)
    }

    @Test func udotVector_2S() {
        let d = decode(0x2F82_E020)
        #expect(d.mnemonic == .udot)
    }

    @Test func umlalVector_4S() {
        let d = decode(0x2F42_2020)
        #expect(d.mnemonic == .umlal)
    }

    @Test func umlslVector_4S() {
        let d = decode(0x2F42_6020)
        #expect(d.mnemonic == .umlsl)
    }

    @Test func umullVector_4S() {
        let d = decode(0x2F42_A020)
        #expect(d.mnemonic == .umull)
    }

    @Test func reservedFPSizeAndQReturnsUndefined() {
        // FP family sz=1 Q=0 reserved.
        let d = decode(0x0FC2_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntSizeReturnsUndefined() {
        // U=1, size=00, L=1, opcode=0000: no x-indexed mapping; reserved.
        // (The U=0 form 0x0F22_0020 is the valid FDOT by-element.)
        let d = decode(0x2F22_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        // U=1, size=01, opcode=1001 (sz/opcode combination with no
        // integer or FP x-indexed mapping); reserved.
        let d = decode(0x2F42_9020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector three-reg-extension — SDOT/UDOT/USDOT/SMMLA/
/// UMMLA/USMMLA/BFMMLA/BFMLALB.
@Suite("SIMD/FP / AdvSIMD three-reg-extension")
struct AdvSIMDVectorThreeRegExtensionTests {
    @Test func sdotVector_4S() {
        // SDOT V0.4S, V1.16B, V2.16B: Q=1, U=0, size=10, opcode=1001.
        let d = decode(0x4E82_9420)
        #expect(d.mnemonic == .sdot)
    }

    @Test func udotVector_4S() {
        // UDOT V0.4S, V1.16B, V2.16B: U=1, size=10, opcode=1001.
        let d = decode(0x6E82_9420)
        #expect(d.mnemonic == .udot)
    }

    @Test func usdotVector_4S() {
        // USDOT V0.4S, V1.16B, V2.16B: U=0, size=10, opcode=1001 with bit10=1.
        let d = decode(0x4E82_9C20)
        #expect(d.mnemonic == .usdot)
    }

    @Test func smmlaVector_4S() {
        // SMMLA V0.4S, V1.16B, V2.16B: U=0, size=10, opcode=1010.
        let d = decode(0x4E82_A420)
        #expect(d.mnemonic == .smmla)
    }

    @Test func ummlaVector_4S() {
        // UMMLA V0.4S, V1.16B, V2.16B: U=1, size=10, opcode=1010.
        let d = decode(0x6E82_A420)
        #expect(d.mnemonic == .ummla)
    }

    @Test func bfmmlaVector_4S() {
        // BFMMLA V0.4S, V1.8H, V2.8H: U=1, size=01, opcode=1011.
        let d = decode(0x6E42_EC20)
        #expect(d.mnemonic == .bfmmla)
    }

    @Test func usmmlaVector_4S() {
        // USMMLA V0.4S, V1.16B, V2.16B: U=0, size=10, opcode=1010 with bit10=1.
        let d = decode(0x4E82_AC20)
        #expect(d.mnemonic == .usmmla)
    }

    @Test func bfmlalbVector_4S() {
        // BFMLALB V0.4S, V1.8H, V2.8H: U=0, size=11, opcode=1111.
        let d = decode(0x2EC2_FC20)
        #expect(d.mnemonic == .bfmlalb)
    }

    @Test func reservedReturnsUndefined() {
        // U=1, size=10, opcode=0001 — not in the three-reg-extension table.
        let d = decode(0x6E82_3420)
        #expect(d.mnemonic == .undefined)
    }
}

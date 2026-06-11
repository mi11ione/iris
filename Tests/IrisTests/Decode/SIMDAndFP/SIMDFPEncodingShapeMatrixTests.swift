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

/// Targets the AdvSIMD vector-copy element-shape variants that
/// SIMDFPAdvSIMDVectorMiscTests didn't already hit (DUP-element H/S/D
/// arrangements with Q=0/1, INS-element, INS-general D-form, UMOV H).
@Suite("SIMD/FP / AdvSIMD copy element matrix")
struct AdvSIMDCopyElementMatrixTests {
    @Test func dupElementH4FromHalf() {
        // DUP V0.4H, V1.H[0]: imm5=00010 (H, idx 0), op=0, imm4=0000, Q=0.
        let d = decode(0x0E02_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementS2FromSingle() {
        // DUP V0.2S, V1.S[0]: imm5=00100 (S), Q=0.
        let d = decode(0x0E04_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func insGeneralDFromX() {
        // INS V0.D[0], X1: op=0, imm4=0011, imm5=01000 (D), Q=1.
        let d = decode(0x4E08_1C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovHWFromHalfElement() {
        // UMOV W0, V1.H[0]: op=0, imm4=0111, imm5=00010 (H), Q=0.
        let d = decode(0x0E02_3C20)
        #expect(d.mnemonic == .umov)
    }

    @Test func insElementHToH() {
        // INS V0.H[0], V1.H[0]: op=1, imm5=00010 (H), Q=1.
        let d = decode(0x6E02_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementSToS() {
        // INS V0.S[0], V1.S[0]: op=1, imm5=00100 (S), Q=1.
        let d = decode(0x6E04_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementDToD() {
        // INS V0.D[0], V1.D[0]: op=1, imm5=01000 (D), Q=1.
        let d = decode(0x6E08_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementH8Q1() {
        // DUP V0.8H, V1.H[0]: imm5=00010 Q=1.
        let d = decode(0x4E02_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementS4Q1() {
        // DUP V0.4S, V1.S[0]: imm5=00100 Q=1.
        let d = decode(0x4E04_0420)
        #expect(d.mnemonic == .dup)
    }
}

/// Targets AdvSIMD multi-structure encodings beyond ST4/LD4 — ST1 with
/// rpt=4/3/2, ST3, ST2 variants.
@Suite("SIMD/FP / Multi-structure opcode matrix")
struct MultiStructureOpcodeMatrixTests {
    @Test func st1MultiFourRegs() {
        // ST1 {V0.8B-V3.8B}: opcode=0010.
        let d = decodeLS(0x0C00_2000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiThreeRegs() {
        // ST1 {V0.8B-V2.8B}: opcode=0110.
        let d = decodeLS(0x0C00_6000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiTwoRegs() {
        // ST1 {V0.8B-V1.8B}: opcode=1010.
        let d = decodeLS(0x0C00_A000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1MultiFourRegs() {
        // LD1 {V0.8B-V3.8B}: opcode=0010, L=1. byte 1 = 0x40.
        let d = decodeLS(0x0C40_2000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiThreeRegs() {
        // LD1 {V0.8B-V2.8B}: opcode=0110, L=1.
        let d = decodeLS(0x0C40_6000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiOneReg() {
        // LD1 {V0.8B}: opcode=0111, L=1.
        let d = decodeLS(0x0C40_7000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiTwoRegs() {
        // LD1 {V0.8B-V1.8B}: opcode=1010, L=1.
        let d = decodeLS(0x0C40_A000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld3MultiStructure() {
        // LD3: opcode=0100, L=1.
        let d = decodeLS(0x0C40_4000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func ld2MultiStructure() {
        // LD2: opcode=1000, L=1.
        let d = decodeLS(0x0C40_8000)
        #expect(d.mnemonic == .ld2)
    }
}

/// Targets remaining AdvSIMD single-structure encoding paths — ST3
/// single-element forms, LD2 single-element, LD3R/LD4R.
@Suite("SIMD/FP / Single-structure opcode matrix")
struct SingleStructureOpcodeMatrixTests {
    @Test func ld3SingleStructureByteElement() {
        // LD3 {V0-V2}.B[0]: opcode=001, R=0, L=1.
        let d = decodeLS(0x0D40_2000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func st4SingleStructureByteElement() {
        // ST4 {V0-V3}.B[0]: opcode=001, R=1, L=0.
        let d = decodeLS(0x0D20_2000)
        #expect(d.mnemonic == .st4)
    }

    @Test func ld2SingleStructureWordElement() {
        // LD2 {V0-V1}.S[0]: opcode=100, R=1, L=1. byte 2 = 1000_0000 = 0x80.
        let d = decodeLS(0x0D60_8000)
        #expect(d.mnemonic == .ld2)
    }

    @Test func st1SingleStructureHalfwordElementR0() {
        // ST1 {V0.H[0]}: opcode=010, R=0, L=0.
        let d = decodeLS(0x0D00_4000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld3rReplicate() {
        // LD3R: opcode=111, R=0, L=1.
        let d = decodeLS(0x0D40_E000)
        #expect(d.mnemonic == .ld3r)
    }
}

/// Targets AdvSIMD modified-immediate shift-zero and op-variant paths.
@Suite("SIMD/FP / Modified-immediate variants")
struct ModifiedImmediateVariantTests {
    @Test func moviSWithLslShift8() {
        // MOVI V0.2S, #1, LSL #8: cmode=0010 (shift=8).
        let d = decode(0x0F00_2400)
        #expect(d.mnemonic == .movi)
    }

    @Test func orrImmSSWithShiftZero() {
        // ORR Vd.2S, #1: cmode=0001 (shift=0).
        let d = decode(0x0F00_1400)
        #expect(d.mnemonic == .orr)
    }

    @Test func mvni16BitShifted() {
        // MVNI V0.4H, #1, LSL #8: cmode=1010 (shift=8), op=1.
        let d = decode(0x2F00_A400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func bicImm16BitShiftZero() {
        // BIC V0.4H, #1: cmode=1001, op=1, shift=0.
        let d = decode(0x2F00_9400)
        #expect(d.mnemonic == .bic)
    }

    @Test func mvniMSLShift16() {
        // MVNI V0.4S, #0, MSL #16: cmode=1101, op=1.
        let d = decode(0x2F00_D400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func mvni16BitShiftZero() {
        // MVNI V0.4H, #0: cmode=1000, op=1, shift=0.
        let d = decode(0x2F00_8400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func orrImm16BitShifted() {
        // ORR V0.4H, #0, LSL #8: cmode=1011, op=0, shamt=8.
        let d = decode(0x0F00_B400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImm16BitShifted() {
        // BIC V0.4H, #0, LSL #8: cmode=1011, op=1, shamt=8.
        let d = decode(0x2F00_B400)
        #expect(d.mnemonic == .bic)
    }

    @Test func orrImm32BitShifted() {
        // ORR V0.2S, #0, LSL #8: cmode=0011 (shift=8), op=0.
        // 0xx1 pattern with non-zero shift → exercises the non-nil
        // shiftOp branch.
        let d = decode(0x0F00_3400)
        #expect(d.mnemonic == .orr)
    }
}

/// Targets AdvSIMD permute with .1D arrangement reserved.
@Suite("SIMD/FP / Permute reserved arrangement")
struct PermuteReservedTests {
    @Test func uzp1Of1DIsReserved() {
        // UZP1 V0.1D, ...: size=11 Q=0 → .d1 reserved. Permute pattern
        // requires bit 21 = 0; byte 1 = 1100_0010 = 0xC2.
        let d = decode(0x0EC2_1820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Targets scalar pairwise / three-same / two-reg-misc FP scalar D-form
/// (sz=1) paths.
@Suite("SIMD/FP / FP scalar D-form pairwise / three-same / two-reg-misc")
struct FPScalarDoubleFormTests {
    @Test func fmaxnmpScalarDoublePair() {
        // FMAXNMP D0, V1.2D: U=1, opcode=01100, sz=1, altBit=0.
        // size = 01 (sz=1, altBit=0). byte 1: 01_1_1000_0 = 0111_0000 = 0x70.
        let d = decode(0x7E70_C820)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpScalarDoublePair() {
        // FMINNMP D0, V1.2D: altBit=1 ⇒ size=11.
        let d = decode(0x7EF0_C820)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func fmulxScalarDouble() {
        // FMULX D0, D1, D2: U=0, opcode=11011, sz=1, altBit=0 ⇒ size=01.
        let d = decode(0x5E62_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcvtnsScalarDouble() {
        // FCVTNS D0, D1: U=0, opcode=11010, sz=1, altBit=0 ⇒ size=01.
        let d = decode(0x5E61_A820)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcmgtZeroScalarDouble() {
        // FCMGT D0, D1, #0.0: U=0, opcode=01100, altBit=1 sz=1 ⇒ size=11.
        let d = decode(0x5EE0_C820)
        #expect(d.mnemonic == .fcmgt)
        // Third operand is .double float immediate.
        if case let .floatImmediate(_, kind) = d.operands[2] {
            #expect(kind == .double)
        }
    }

    @Test func fcmeqZeroScalarDouble() {
        let d = decode(0x5EE0_D820)
        #expect(d.mnemonic == .fcmeq)
    }
}

/// Targets scalar shift-by-immediate H-element forms (immh = 0010).
@Suite("SIMD/FP / Scalar shift-by-immediate H-element")
struct ScalarShiftByImmediateHTests {
    @Test func sqshlScalarHalf() {
        // SQSHL H0, H1, #1: U=0, opcode=01110, immh=0010, immb=001.
        // byte 1 = 0_0010_001 = 0001_0001 = 0x11. byte 2 = 0111_0100 = 0x74.
        let d = decode(0x5F11_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func sqshrnScalarByte() {
        // SQSHRN B0, H1, #1: opcode=10010, immh=0001.
        // byte 1 = 0_0001_111 = 0000_1111 = 0x0F. byte 2 = 1001_0100 = 0x94.
        let d = decode(0x5F0F_9420)
        #expect(d.mnemonic == .sqshrn)
    }
}

/// Targets AdvSIMD scalar x-indexed-element D-form (sz=1) and integer
/// S→D lengthening (size=10) paths.
@Suite("SIMD/FP / Scalar x-indexed D-form + S→D")
struct ScalarXIndexedDoubleFormTests {
    @Test func fmulScalarDouble() {
        // FMUL D0, D1, V2.D[0]: U=0, opcode=1001, sz=1.
        // size=10 (sz=1, L=0). byte 1 = 11_0_0_0010 = 1100_0010 = 0xC2.
        let d = decode(0x5FC2_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func sqdmullScalarSToD() {
        // SQDMULL D0, S1, V2.S[0]: U=0, opcode=1011, size=10 (S → D).
        let d = decode(0x5F82_B020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmlalScalarSToD() {
        let d = decode(0x5F82_3020)
        #expect(d.mnemonic == .sqdmlal)
    }
}

/// Targets AdvSIMD shift-by-immediate Q=1 narrowing-2 forms + various
/// element-size narrowing/lengthening combinations.
@Suite("SIMD/FP / Shift-by-immediate Q=1 narrowing-2 forms")
struct ShiftByImmediateQ1NarrowingTests {
    @Test func shrn2() {
        // SHRN2 V0.16B, V1.8H, #1: Q=1, opcode=10000, immh=0001.
        let d = decode(0x4F0F_8420)
        #expect(d.mnemonic == .shrn2)
    }

    @Test func rshrn2() {
        let d = decode(0x4F0F_8C20)
        #expect(d.mnemonic == .rshrn2)
    }

    @Test func sqshrn2() {
        let d = decode(0x4F0F_9420)
        #expect(d.mnemonic == .sqshrn2)
    }

    @Test func sqrshrn2() {
        let d = decode(0x4F0F_9C20)
        #expect(d.mnemonic == .sqrshrn2)
    }

    @Test func uqshrn2() {
        let d = decode(0x6F0F_9420)
        #expect(d.mnemonic == .uqshrn2)
    }

    @Test func uqrshrn2() {
        let d = decode(0x6F0F_9C20)
        #expect(d.mnemonic == .uqrshrn2)
    }

    @Test func sqshrun2() {
        let d = decode(0x6F0F_8420)
        #expect(d.mnemonic == .sqshrun2)
    }

    @Test func sqrshrun2() {
        let d = decode(0x6F0F_8C20)
        #expect(d.mnemonic == .sqrshrun2)
    }

    @Test func shrnFromSToH() {
        // SHRN V0.4H, V1.4S, #1: opcode=10000, immh=0010 (H).
        let d = decode(0x0F1F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func shrnFromDToS() {
        // SHRN V0.2S, V1.2D, #1: immh=0100 (S source narrowed from D).
        let d = decode(0x0F3F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func sshllNonZeroShiftHToS() {
        // SSHLL V0.4S, V1.4H, #1: opcode=10100, immh=0010, immb=001 ⇒ shift=1.
        let d = decode(0x0F11_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshllNonZeroShiftSToD() {
        // SSHLL V0.2D, V1.2S, #1: immh=0100, immb=001.
        let d = decode(0x0F21_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshrVectorQ1() {
        // SSHR V0.16B, V1.16B, #1: U=0, opcode=00000, immh=0001, Q=1.
        // Exercises q1SuffixedMnemonic default arm (.sshr has no Q-suffix
        // variant; default returns unchanged mnemonic).
        let d = decode(0x4F0F_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func sshll2WithNonZeroShift() {
        // SSHLL2 V0.8H, V1.16B, #1: Q=1, immh=0001, immb=001 ⇒ shift=1.
        // Routes through q1SuffixedMnemonic → .sshll2 (not SXTL2 since
        // shift != 0).
        let d = decode(0x4F09_A420)
        #expect(d.mnemonic == .sshll2)
    }

    @Test func ushll2WithNonZeroShift() {
        // USHLL2 V0.8H, V1.16B, #1: U=1, Q=1.
        let d = decode(0x6F09_A420)
        #expect(d.mnemonic == .ushll2)
    }

    @Test func shrn2FromDToS() {
        // SHRN2 V0.4S, V1.2D, #1: Q=1 D-source narrowing (Q=0 reserved).
        // immh=0111 (2D source), immb=111 ⇒ shift=1.
        let d = decode(0x4F3F_8420)
        #expect(d.mnemonic == .shrn2)
    }

    @Test func shrnFromSToH_actual() {
        // SHRN V0.4H, V1.4S, #1: S source (immh=0111). Q=0.
        // byte 1 = 0_0111_111 = 0x3F.
        let d = decode(0x0F3F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func shrn2FromSToH() {
        // SHRN2 V0.8H, V1.4S, #1: S source Q=1.
        let d = decode(0x4F3F_8420)
        #expect(d.mnemonic == .shrn2)
    }

    @Test func shrn2FromHToB() {
        // SHRN2 V0.16B, V1.8H, #1: H source Q=1.
        let d = decode(0x4F1F_8420)
        #expect(d.mnemonic == .shrn2)
    }
}

/// Targets AdvSIMD vector three-different (size, Q) combinations not
/// already covered.
@Suite("SIMD/FP / Three-different size×Q matrix")
struct ThreeDifferentMatrixTests {
    @Test func saddl2_8H_FromB16() {
        // SADDL2 V0.8H, V1.16B, V2.16B: Q=1 size=00.
        let d = decode(0x4E22_0020)
        #expect(d.mnemonic == .saddl2)
    }

    @Test func saddl_4S_FromH4() {
        // SADDL V0.4S, V1.4H, V2.4H: size=01 Q=0.
        let d = decode(0x0E62_0020)
        #expect(d.mnemonic == .saddl)
    }

    @Test func saddl2_4S_FromH8() {
        // SADDL2 V0.4S, V1.8H, V2.8H: size=01 Q=1.
        let d = decode(0x4E62_0020)
        #expect(d.mnemonic == .saddl2)
    }

    @Test func saddl_2D_FromS2() {
        // SADDL V0.2D, V1.2S, V2.2S: size=10 Q=0.
        let d = decode(0x0EA2_0020)
        #expect(d.mnemonic == .saddl)
    }

    @Test func saddl2_2D_FromS4() {
        // SADDL2 V0.2D, V1.4S, V2.4S: size=10 Q=1.
        let d = decode(0x4EA2_0020)
        #expect(d.mnemonic == .saddl2)
    }
}

/// Targets DOT / USDOT Q=0 forms.
@Suite("SIMD/FP / DOT Q=0 forms")
struct DOTQZeroFormsTests {
    @Test func sdotQZero() {
        // SDOT V0.2S, V1.8B, V2.8B: Q=0, U=0, size=10, opcode=0010.
        // byte 2 = 1_0010_1_00 = 0x94.
        let d = decode(0x0E82_9420)
        #expect(d.mnemonic == .sdot)
    }

    @Test func udotQZero() {
        // U=1.
        let d = decode(0x2E82_9420)
        #expect(d.mnemonic == .udot)
    }

    @Test func usdotQZero() {
        // USDOT V0.2S, V1.8B, V2.8B: Q=0, U=0, size=10, opcode=0011.
        // byte 2 = 1_0011_1_00 = 0x9C.
        let d = decode(0x0E82_9C20)
        #expect(d.mnemonic == .usdot)
    }
}

/// Targets vector three-same FP family Q=1 arrangements (.4S/.2D).
@Suite("SIMD/FP / Vector three-same FP Q=1 arrangements")
struct ThreeSameFPQOneArrangementTests {
    @Test func faddVector_4S() {
        // FADD V0.4S, V1.4S, V2.4S: Q=1, size=00.
        let d = decode(0x4E22_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func faddVector_2D() {
        // FADD V0.2D, V1.2D, V2.2D: Q=1, size=01 (sz=1).
        let d = decode(0x4E62_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func andVector_8B() {
        // AND V0.8B, V1.8B, V2.8B: Q=0, opcode=00011, size=00.
        let d = decode(0x0E22_1C20)
        #expect(d.mnemonic == .and)
    }

    @Test func andVector_16B() {
        // AND V0.16B, V1.16B, V2.16B: Q=1 → exercises `.b16` ternary branch.
        let d = decode(0x4E22_1C20)
        #expect(d.mnemonic == .and)
    }
}

/// Targets vector two-reg-misc FP family Q=1 arrangements + integer
/// SADDLP + SHLL widening + FCMx-zero D-form.
@Suite("SIMD/FP / Vector two-reg-misc extras")
struct TwoRegMiscExtrasTests {
    @Test func saddlpV0_4H_From_8B() {
        // SADDLP V0.4H, V1.8B: opcode=00010, size=00 Q=0.
        let d = decode(0x0E20_2820)
        #expect(d.mnemonic == .saddlp)
    }

    @Test func sadalpV0_4H_From_8B() {
        // SADALP V0.4H, V1.8B: opcode=00110, size=00 Q=0. byte 2 = 0110_1000 = 0x68.
        let d = decode(0x0E20_6820)
        #expect(d.mnemonic == .sadalp)
    }

    @Test func shllV0_8H_From_8B() {
        // SHLL V0.8H, V1.8B, #8: U=1, opcode=10011, size=00 Q=0.
        let d = decode(0x2E21_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func shllV0_4S_From_4H() {
        // size=01.
        let d = decode(0x2E61_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func shllV0_2D_From_2S() {
        let d = decode(0x2EA1_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func frintnVector_4S() {
        // FRINTN V0.4S, V1.4S: Q=1.
        let d = decode(0x4E21_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func frintnVector_2D() {
        // FRINTN V0.2D, V1.2D: Q=1 sz=1.
        let d = decode(0x4E61_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func fcmgtZeroVector_2D() {
        // FCMGT V0.2D, V1.2D, #0.0: Q=1 sz=1.
        let d = decode(0x4EE0_C820)
        #expect(d.mnemonic == .fcmgt)
        if case let .floatImmediate(_, kind) = d.operands[2] {
            #expect(kind == .double)
        }
    }
}

/// Targets vector x-indexed-element integer-family size/Q variants.
@Suite("SIMD/FP / Vector x-indexed int matrix")
struct VectorXIndexedIntMatrixTests {
    @Test func mulV0_8H_FromH8() {
        // MUL V0.8H, V1.8H, V2.H[0]: size=01, Q=1.
        let d = decode(0x4F42_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func mulV0_2S_FromS2() {
        // MUL V0.2S, V1.2S, V2.S[0]: size=10, Q=0.
        let d = decode(0x0F82_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func smlalV0_4S_FromH4() {
        // SMLAL V0.4S, V1.4H, V2.H[0]: size=01, Q=0 → dst .s4.
        let d = decode(0x0F42_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func smlalV0_2D_FromS2() {
        // SMLAL V0.2D, V1.2S, V2.S[0]: size=10, Q=0 → dst .d2.
        let d = decode(0x0F82_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func reservedFPVectorXIndexed() {
        // (U=1, opcode=0001) reserved (FMLA isn't U=1).
        let d = decode(0x2F82_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func mulV0_4S_FromS4Q1() {
        // MUL V0.4S, V1.4S, V2.S[0]: U=0, size=10, Q=1, opcode=1000.
        // Exercises (size=10, Q=1) → elementSize=.s, srcArrangement=.s4 path.
        let d = decode(0x4F82_8020)
        #expect(d.mnemonic == .mul)
    }
}

/// Targets scalar SIMD LDP/STP post-indexed STP path (L=0).
@Suite("SIMD/FP / Scalar SIMD STP post-indexed")
struct ScalarSIMDStpPostIndexedTests {
    @Test func stpSingleScalarPostIndexed() {
        // STP S0, S1, [X0], #0: opc=00, indexing=01, L=0.
        // top byte 0x2C. byte 1: bit 23 = 1, L = 0 ⇒ 1000_0000 = 0x80.
        let d = decodeLS(0x2C80_0400)
        #expect(d.mnemonic == .stp)
    }
}

/// Targets ScalarSIMD register-offset L/S with shift-bit S=1 (exercises
/// logBytes scalar-size switch arms).
@Suite("SIMD/FP / ScalarSIMD register-offset with S=1 shift")
struct ScalarSIMDRegisterOffsetShiftTests {
    @Test func ldrByteRegisterOffsetShiftedZero() {
        // LDR B0, [X0, X1, UXTW]: size=00, opc=01, bits[11:10]=10, S=0.
        // option=010. byte 2 = 0100_1000 = 0x48.
        let d = decodeLS(0x3C61_4800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrByteRegisterOffsetShifted() {
        // LDR B0, [X0, X1, UXTW #0]: S=1 with B-element ⇒ shift=0.
        // S=1 ⇒ byte 2 bit 4 = 1 ⇒ byte 2 = 0101_1000 = 0x58.
        let d = decodeLS(0x3C61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrHalfRegisterOffsetShifted() {
        // LDR H0, [X0, X1, UXTW #1]: size=01, S=1 ⇒ shift=log2(2)=1.
        let d = decodeLS(0x7C61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrSingleRegisterOffsetShifted() {
        // LDR S0, [X0, X1, UXTW #2]: size=10, S=1 ⇒ shift=2.
        let d = decodeLS(0xBC61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrDoubleRegisterOffsetShifted() {
        // LDR D0, [X0, X1, UXTW #3]: size=11.
        let d = decodeLS(0xFC61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrQuadRegisterOffsetShifted() {
        // LDR Q0, [X0, X1, UXTW #4]: size=00 opc=11.
        let d = decodeLS(0x3CE1_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strSingleRegisterOffset() {
        // STR S0, [X0, X1, UXTW]: size=10 opc=00 (store).
        let d = decodeLS(0xBC21_4800)
        #expect(d.mnemonic == .str)
    }

    @Test func strSinglePostIndexed() {
        // STR S0, [X0], #0: size=10 opc=00 bits[11:10]=01.
        let d = decodeLS(0xBC00_0400)
        #expect(d.mnemonic == .str)
    }

    @Test func strSinglePreIndexed() {
        // STR S0, [X0, #0]!: bits[11:10]=11.
        let d = decodeLS(0xBC00_0C00)
        #expect(d.mnemonic == .str)
    }
}

/// Targets SIMDFPCommon register-31 mappings (XZR/WZR/WSP via SCVTF
/// fixed-point Rn=31 paths).
@Suite("SIMD/FP / Register-31 GPR mappings")
struct Register31GPRTests {
    @Test func fmovWFromSWithRdEquals31() {
        // FMOV W31 (WZR), S1: sf=0, ftype=00, rmode=00, opcode=110.
        // byte 3: Rn=1 (bit 5), Rd=11111 (bits 4..0) = 0011_1111 = 0x3F.
        let d = decode(0x1E26_003F)
        #expect(d.mnemonic == .fmov)
    }

    @Test func ldrSingleWithSPBase() {
        // LDR S0, [SP]: Rn=31, SP base.
        let d = decodeLS(0xBD40_03E0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func fcvtzsXZRFromS() {
        // FCVTZS XZR, S1: sf=1, ftype=00, rmode=11, opcode=000, Rd=31.
        // top byte 0x9E. byte 1 = 0001_1000 = 0x18. byte 2 = 0x00.
        // byte 3 = bit 5 (Rn=0), bits 4..0 (Rd=11111) = 0001_1111 = 0x1F.
        // Exercises simdfpGprOperand's masked==31 spOrGeneral=false x64 → XZR.
        let d = decode(0x9E18_001F)
        #expect(d.mnemonic == .fcvtzs)
    }
}

/// Targets SIMDFPCanonicalizer's scalar-suffix paths for H/S/D
/// element-view operands (element-view always uses .b/.h/.s/.d — never
/// .q — so the .q arm in scalarSuffix is genuinely unreachable from
/// the public API).
@Suite("SIMD/FP / Canonicalizer element-view suffix coverage")
struct CanonicalizerElementViewSuffixTests {
    private func draft(view: VectorView) -> Instruction {
        let op = Operand.vectorRegister(VectorRegisterRef(registerIndex: 0, view: view))
        return Instruction(
            address: 0, encoding: 0, mnemonic: .mov,
            category: .simdAndFP, operands: [op],
        )
    }

    @Test func bElementSuffixRenders() {
        let d = draft(view: .element(arrangement: .b16, index: 0))
        #expect(d.text == "mov v0.b[0]")
    }

    @Test func hElementSuffixRenders() {
        let d = draft(view: .element(arrangement: .h8, index: 0))
        #expect(d.text == "mov v0.h[0]")
    }

    @Test func sElementSuffixRenders() {
        let d = draft(view: .element(arrangement: .s4, index: 0))
        #expect(d.text == "mov v0.s[0]")
    }

    @Test func dElementSuffixRenders() {
        let d = draft(view: .element(arrangement: .d2, index: 0))
        #expect(d.text == "mov v0.d[0]")
    }
}

/// Targets memoryText with index + non-zero shift (LDR with S=1).
@Suite("SIMD/FP / Canonicalizer memory shift")
struct CanonicalizerMemoryShiftTests {
    @Test func memoryWithIndexAndShiftRenders() {
        let mem = MemoryOperand(
            base: .register(.x(0)), index: .x(1),
            extend: .lsl, shift: 2,
        )
        let op = Operand.memory(mem)
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: .ldr,
            category: .simdAndFP, operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
                op,
            ],
        )
        #expect(d.text == "ldr s0, [x0, x1, lsl #2]")
    }

    @Test func memoryWithIndexAndExtendZeroShiftRenders() {
        // Exercise the inner `mem.shift == 0xFF ? "" : "..."` ternary's
        // suppressed-shift branch (sentinel 0xFF) with a non-none extend:
        // the extend kind renders without a trailing shift amount.
        let mem = MemoryOperand(
            base: .register(.x(0)), index: .x(1),
            extend: .uxtw, shift: 0xFF,
        )
        let op = Operand.memory(mem)
        let d = Instruction(
            address: 0, encoding: 0, mnemonic: .ldr,
            category: .simdAndFP, operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .scalar(size: .s))),
                op,
            ],
        )
        #expect(d.text == "ldr s0, [x0, x1, uxtw]")
    }
}

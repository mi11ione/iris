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

/// Targets the vector-copy element-shape variants the misc suite misses.
@Suite("SIMD/FP / AdvSIMD copy element matrix")
struct AdvSIMDCopyElementMatrixTests {
    @Test func dupElementH4FromHalf() {
        let d = decode(0x0E02_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementS2FromSingle() {
        let d = decode(0x0E04_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func insGeneralDFromX() {
        let d = decode(0x4E08_1C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovHWFromHalfElement() {
        let d = decode(0x0E02_3C20)
        #expect(d.mnemonic == .umov)
    }

    @Test func insElementHToH() {
        let d = decode(0x6E02_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementSToS() {
        let d = decode(0x6E04_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementDToD() {
        let d = decode(0x6E08_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementH8Q1() {
        let d = decode(0x4E02_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementS4Q1() {
        let d = decode(0x4E04_0420)
        #expect(d.mnemonic == .dup)
    }
}

/// Targets AdvSIMD multi-structure encodings beyond ST4/LD4.
@Suite("SIMD/FP / Multi-structure opcode matrix")
struct MultiStructureOpcodeMatrixTests {
    @Test func st1MultiFourRegs() {
        let d = decodeLS(0x0C00_2000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiThreeRegs() {
        let d = decodeLS(0x0C00_6000)
        #expect(d.mnemonic == .st1)
    }

    @Test func st1MultiTwoRegs() {
        let d = decodeLS(0x0C00_A000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld1MultiFourRegs() {
        let d = decodeLS(0x0C40_2000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiThreeRegs() {
        let d = decodeLS(0x0C40_6000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiOneReg() {
        let d = decodeLS(0x0C40_7000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld1MultiTwoRegs() {
        let d = decodeLS(0x0C40_A000)
        #expect(d.mnemonic == .ld1)
    }

    @Test func ld3MultiStructure() {
        let d = decodeLS(0x0C40_4000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func ld2MultiStructure() {
        let d = decodeLS(0x0C40_8000)
        #expect(d.mnemonic == .ld2)
    }
}

/// Targets remaining AdvSIMD single-structure encoding paths.
@Suite("SIMD/FP / Single-structure opcode matrix")
struct SingleStructureOpcodeMatrixTests {
    @Test func ld3SingleStructureByteElement() {
        let d = decodeLS(0x0D40_2000)
        #expect(d.mnemonic == .ld3)
    }

    @Test func st4SingleStructureByteElement() {
        let d = decodeLS(0x0D20_2000)
        #expect(d.mnemonic == .st4)
    }

    @Test func ld2SingleStructureWordElement() {
        let d = decodeLS(0x0D60_8000)
        #expect(d.mnemonic == .ld2)
    }

    @Test func st1SingleStructureHalfwordElementR0() {
        let d = decodeLS(0x0D00_4000)
        #expect(d.mnemonic == .st1)
    }

    @Test func ld3rReplicate() {
        let d = decodeLS(0x0D40_E000)
        #expect(d.mnemonic == .ld3r)
    }
}

/// Targets AdvSIMD modified-immediate shift-zero and op-variant paths.
@Suite("SIMD/FP / Modified-immediate variants")
struct ModifiedImmediateVariantTests {
    @Test func moviSWithLslShift8() {
        let d = decode(0x0F00_2400)
        #expect(d.mnemonic == .movi)
    }

    @Test func orrImmSSWithShiftZero() {
        let d = decode(0x0F00_1400)
        #expect(d.mnemonic == .orr)
    }

    @Test func mvni16BitShifted() {
        let d = decode(0x2F00_A400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func bicImm16BitShiftZero() {
        let d = decode(0x2F00_9400)
        #expect(d.mnemonic == .bic)
    }

    @Test func mvniMSLShift16() {
        let d = decode(0x2F00_D400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func mvni16BitShiftZero() {
        let d = decode(0x2F00_8400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func orrImm16BitShifted() {
        let d = decode(0x0F00_B400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImm16BitShifted() {
        let d = decode(0x2F00_B400)
        #expect(d.mnemonic == .bic)
    }

    @Test func orrImm32BitShifted() {
        let d = decode(0x0F00_3400)
        #expect(d.mnemonic == .orr)
    }
}

/// Targets AdvSIMD permute with .1D arrangement reserved.
@Suite("SIMD/FP / Permute reserved arrangement")
struct PermuteReservedTests {
    @Test func uzp1Of1DIsReserved() {
        let d = decode(0x0EC2_1820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Targets scalar pairwise / three-same / two-reg-misc FP scalar D-form (sz=1)
/// paths.
@Suite("SIMD/FP / FP scalar D-form pairwise / three-same / two-reg-misc")
struct FPScalarDoubleFormTests {
    @Test func fmaxnmpScalarDoublePair() {
        let d = decode(0x7E70_C820)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpScalarDoublePair() {
        let d = decode(0x7EF0_C820)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func fmulxScalarDouble() {
        let d = decode(0x5E62_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcvtnsScalarDouble() {
        let d = decode(0x5E61_A820)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcmgtZeroScalarDouble() {
        let d = decode(0x5EE0_C820)
        #expect(d.mnemonic == .fcmgt)
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
        let d = decode(0x5F11_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func sqshrnScalarByte() {
        let d = decode(0x5F0F_9420)
        #expect(d.mnemonic == .sqshrn)
    }
}

/// Targets AdvSIMD scalar x-indexed-element D-form (sz=1) and integer S→D
/// lengthening (size=10) paths.
@Suite("SIMD/FP / Scalar x-indexed D-form + S→D")
struct ScalarXIndexedDoubleFormTests {
    @Test func fmulScalarDouble() {
        let d = decode(0x5FC2_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func sqdmullScalarSToD() {
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
        let d = decode(0x0F1F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func shrnFromDToS() {
        let d = decode(0x0F3F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func sshllNonZeroShiftHToS() {
        let d = decode(0x0F11_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshllNonZeroShiftSToD() {
        let d = decode(0x0F21_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshrVectorQ1() {
        let d = decode(0x4F0F_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func sshll2WithNonZeroShift() {
        let d = decode(0x4F09_A420)
        #expect(d.mnemonic == .sshll2)
    }

    @Test func ushll2WithNonZeroShift() {
        let d = decode(0x6F09_A420)
        #expect(d.mnemonic == .ushll2)
    }

    @Test func shrn2FromDToS() {
        let d = decode(0x4F3F_8420)
        #expect(d.mnemonic == .shrn2)
    }

    @Test func shrnFromSToH_actual() {
        let d = decode(0x0F3F_8420)
        #expect(d.mnemonic == .shrn)
    }

    @Test func shrn2FromSToH() {
        let d = decode(0x4F3F_8420)
        #expect(d.mnemonic == .shrn2)
    }

    @Test func shrn2FromHToB() {
        let d = decode(0x4F1F_8420)
        #expect(d.mnemonic == .shrn2)
    }
}

/// Targets AdvSIMD vector three-different (size, Q) combinations not already
/// covered.
@Suite("SIMD/FP / Three-different size×Q matrix")
struct ThreeDifferentMatrixTests {
    @Test func saddl2_8H_FromB16() {
        let d = decode(0x4E22_0020)
        #expect(d.mnemonic == .saddl2)
    }

    @Test func saddl_4S_FromH4() {
        let d = decode(0x0E62_0020)
        #expect(d.mnemonic == .saddl)
    }

    @Test func saddl2_4S_FromH8() {
        let d = decode(0x4E62_0020)
        #expect(d.mnemonic == .saddl2)
    }

    @Test func saddl_2D_FromS2() {
        let d = decode(0x0EA2_0020)
        #expect(d.mnemonic == .saddl)
    }

    @Test func saddl2_2D_FromS4() {
        let d = decode(0x4EA2_0020)
        #expect(d.mnemonic == .saddl2)
    }
}

/// Targets DOT / USDOT Q=0 forms.
@Suite("SIMD/FP / DOT Q=0 forms")
struct DOTQZeroFormsTests {
    @Test func sdotQZero() {
        let d = decode(0x0E82_9420)
        #expect(d.mnemonic == .sdot)
    }

    @Test func udotQZero() {
        let d = decode(0x2E82_9420)
        #expect(d.mnemonic == .udot)
    }

    @Test func usdotQZero() {
        let d = decode(0x0E82_9C20)
        #expect(d.mnemonic == .usdot)
    }
}

/// Targets vector three-same FP family Q=1 arrangements (.4S/.2D).
@Suite("SIMD/FP / Vector three-same FP Q=1 arrangements")
struct ThreeSameFPQOneArrangementTests {
    @Test func faddVector_4S() {
        let d = decode(0x4E22_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func faddVector_2D() {
        let d = decode(0x4E62_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func andVector_8B() {
        let d = decode(0x0E22_1C20)
        #expect(d.mnemonic == .and)
    }

    @Test func andVector_16B() {
        let d = decode(0x4E22_1C20)
        #expect(d.mnemonic == .and)
    }
}

/// Targets vector two-reg-misc FP family Q=1 arrangements + integer SADDLP +
/// SHLL widening + FCMx-zero D-form.
@Suite("SIMD/FP / Vector two-reg-misc extras")
struct TwoRegMiscExtrasTests {
    @Test func saddlpV0_4H_From_8B() {
        let d = decode(0x0E20_2820)
        #expect(d.mnemonic == .saddlp)
    }

    @Test func sadalpV0_4H_From_8B() {
        let d = decode(0x0E20_6820)
        #expect(d.mnemonic == .sadalp)
    }

    @Test func shllV0_8H_From_8B() {
        let d = decode(0x2E21_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func shllV0_4S_From_4H() {
        let d = decode(0x2E61_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func shllV0_2D_From_2S() {
        let d = decode(0x2EA1_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func frintnVector_4S() {
        let d = decode(0x4E21_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func frintnVector_2D() {
        let d = decode(0x4E61_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func fcmgtZeroVector_2D() {
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
        let d = decode(0x4F42_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func mulV0_2S_FromS2() {
        let d = decode(0x0F82_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func smlalV0_4S_FromH4() {
        let d = decode(0x0F42_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func smlalV0_2D_FromS2() {
        let d = decode(0x0F82_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func reservedFPVectorXIndexed() {
        let d = decode(0x2F82_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func mulV0_4S_FromS4Q1() {
        let d = decode(0x4F82_8020)
        #expect(d.mnemonic == .mul)
    }
}

/// Targets scalar SIMD LDP/STP post-indexed STP path (L=0).
@Suite("SIMD/FP / Scalar SIMD STP post-indexed")
struct ScalarSIMDStpPostIndexedTests {
    @Test func stpSingleScalarPostIndexed() {
        let d = decodeLS(0x2C80_0400)
        #expect(d.mnemonic == .stp)
    }
}

/// Targets ScalarSIMD register-offset L/S with shift-bit S=1 (exercises
/// logBytes scalar-size switch arms).
@Suite("SIMD/FP / ScalarSIMD register-offset with S=1 shift")
struct ScalarSIMDRegisterOffsetShiftTests {
    @Test func ldrByteRegisterOffsetShiftedZero() {
        let d = decodeLS(0x3C61_4800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrByteRegisterOffsetShifted() {
        let d = decodeLS(0x3C61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrHalfRegisterOffsetShifted() {
        let d = decodeLS(0x7C61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrSingleRegisterOffsetShifted() {
        let d = decodeLS(0xBC61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrDoubleRegisterOffsetShifted() {
        let d = decodeLS(0xFC61_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func ldrQuadRegisterOffsetShifted() {
        let d = decodeLS(0x3CE1_5800)
        #expect(d.mnemonic == .ldr)
    }

    @Test func strSingleRegisterOffset() {
        let d = decodeLS(0xBC21_4800)
        #expect(d.mnemonic == .str)
    }

    @Test func strSinglePostIndexed() {
        let d = decodeLS(0xBC00_0400)
        #expect(d.mnemonic == .str)
    }

    @Test func strSinglePreIndexed() {
        let d = decodeLS(0xBC00_0C00)
        #expect(d.mnemonic == .str)
    }
}

/// Targets SIMDFPCommon register-31 mappings (XZR/WZR/WSP via SCVTF
/// fixed-point Rn=31 paths).
@Suite("SIMD/FP / Register-31 GPR mappings")
struct Register31GPRTests {
    @Test func fmovWFromSWithRdEquals31() {
        let d = decode(0x1E26_003F)
        #expect(d.mnemonic == .fmov)
    }

    @Test func ldrSingleWithSPBase() {
        let d = decodeLS(0xBD40_03E0)
        #expect(d.mnemonic == .ldr)
    }

    @Test func fcvtzsXZRFromS() {
        let d = decode(0x9E18_001F)
        #expect(d.mnemonic == .fcvtzs)
    }
}

/// Targets the canonicalizer's scalar-suffix paths for H/S/D element-view
/// operands; element views never use `.q`, so that arm is unreachable from
/// the.
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

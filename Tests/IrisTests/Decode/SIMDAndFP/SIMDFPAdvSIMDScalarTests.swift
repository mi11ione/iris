// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD scalar three-same.
@Suite("SIMD/FP / AdvSIMD scalar three-same")
struct AdvSIMDScalarThreeSameTests {
    @Test func sqaddDoubleScalar() {
        let d = decode(0x5EE2_0C20)
        #expect(d.mnemonic == .sqadd)
    }

    @Test func uqaddDoubleScalar() {
        let d = decode(0x7EE2_0C20)
        #expect(d.mnemonic == .uqadd)
    }

    @Test func sqsubDoubleScalar() {
        let d = decode(0x5EE2_2C20)
        #expect(d.mnemonic == .sqsub)
    }

    @Test func uqsubDoubleScalar() {
        let d = decode(0x7EE2_2C20)
        #expect(d.mnemonic == .uqsub)
    }

    @Test func cmgtDoubleScalar() {
        let d = decode(0x5EE2_3420)
        #expect(d.mnemonic == .cmgt)
    }

    @Test func cmgeDoubleScalar() {
        let d = decode(0x5EE2_3C20)
        #expect(d.mnemonic == .cmge)
    }

    @Test func sshlDoubleScalar() {
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
        let d = decode(0x5EE2_8420)
        #expect(d.mnemonic == .add)
    }

    @Test func subDoubleScalar() {
        let d = decode(0x7EE2_8420)
        #expect(d.mnemonic == .sub)
    }

    @Test func cmtstDoubleScalar() {
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
        let d = decode(0x5E62_B420)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhHalfScalar() {
        let d = decode(0x7E62_B420)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func fmulxScalarSingle() {
        let d = decode(0x5E22_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcmeqScalarSingle() {
        let d = decode(0x5E22_E420)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func frecpsScalarSingle() {
        let d = decode(0x5E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func frsqrtsScalarSingle() {
        let d = decode(0x5EA2_FC20)
        #expect(d.mnemonic == .frsqrts)
    }

    @Test func fcmgeScalarSingle() {
        let d = decode(0x7E22_E420)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmgtScalarSingle() {
        let d = decode(0x7EA2_E420)
        #expect(d.mnemonic == .fcmgt)
    }

    @Test func facgeScalarSingle() {
        let d = decode(0x7E22_EC20)
        #expect(d.mnemonic == .facge)
    }

    @Test func facgtScalarSingle() {
        let d = decode(0x7EA2_EC20)
        #expect(d.mnemonic == .facgt)
    }

    @Test func fabdScalarSingle() {
        let d = decode(0x7EA2_D420)
        #expect(d.mnemonic == .fabd)
    }

    @Test func reservedFPSizeReturnsUndefined() {
        let d = decode(0x5EA2_E420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        let d = decode(0x5EE2_A420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar three-different.
@Suite("SIMD/FP / AdvSIMD scalar three-different")
struct AdvSIMDScalarThreeDifferentTests {
    @Test func sqdmlalScalarHToS() {
        let d = decode(0x5E62_9020)
        #expect(d.mnemonic == .sqdmlal)
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func sqdmlslScalarHToS() {
        let d = decode(0x5E62_B020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmullScalarHToS() {
        let d = decode(0x5E62_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmullScalarSToD() {
        let d = decode(0x5EA2_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func reservedSizeReturnsUndefined() {
        let d = decode(0x5E22_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSize11ReturnsUndefined() {
        let d = decode(0x5EE2_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedUEqualsOneReturnsUndefined() {
        let d = decode(0x7E62_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        let d = decode(0x5E62_8020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar two-reg-misc.
@Suite("SIMD/FP / AdvSIMD scalar two-reg-misc")
struct AdvSIMDScalarTwoRegMiscTests {
    @Test func sqabsDoubleScalar() {
        let d = decode(0x5EE0_7820)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func sqnegDoubleScalar() {
        let d = decode(0x7EE0_7820)
        #expect(d.mnemonic == .sqneg)
    }

    @Test func absDoubleScalar() {
        let d = decode(0x5EE0_B820)
        #expect(d.mnemonic == .abs)
    }

    @Test func negDoubleScalar() {
        let d = decode(0x7EE0_B820)
        #expect(d.mnemonic == .neg)
    }

    @Test func cmgtZeroDoubleScalar() {
        let d = decode(0x5EE0_8820)
        #expect(d.mnemonic == .cmgt)
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
        let d = decode(0x5EE0_3820)
        #expect(d.mnemonic == .suqadd)
    }

    @Test func usqaddScalar() {
        let d = decode(0x7EE0_3820)
        #expect(d.mnemonic == .usqadd)
    }

    @Test func sqxtnByteScalar() {
        let d = decode(0x5E21_4820)
        #expect(d.mnemonic == .sqxtn)
    }

    @Test func uqxtnByteScalar() {
        let d = decode(0x7E21_4820)
        #expect(d.mnemonic == .uqxtn)
    }

    @Test func sqxtunByteScalar() {
        let d = decode(0x7E21_2820)
        #expect(d.mnemonic == .sqxtun)
    }

    @Test func fcvtnsScalarSingle() {
        let d = decode(0x5E21_A820)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcvtpsScalarSingle() {
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
        let d = decode(0x5E21_C820)
        #expect(d.mnemonic == .fcvtas)
    }

    @Test func scvtfScalarSingle() {
        let d = decode(0x5E21_D820)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func frecpeScalarSingle() {
        let d = decode(0x5EA1_D820)
        #expect(d.mnemonic == .frecpe)
    }

    @Test func frecpxScalarSingle() {
        let d = decode(0x5EA1_F820)
        #expect(d.mnemonic == .frecpx)
    }

    @Test func fsqrtScalarSingle() {
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
        let d = decode(0x7EA1_D820)
        #expect(d.mnemonic == .frsqrte)
    }

    @Test func fcmgtZeroScalarSingle() {
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
        let d = decode(0x5EE0_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedFPScalarTwoRegMiscReturnsUndefined() {
        let d = decode(0x5EA1_C820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar pairwise.
@Suite("SIMD/FP / AdvSIMD scalar pairwise")
struct AdvSIMDScalarPairwiseTests {
    @Test func addpScalarDoublePair() {
        let d = decode(0x5EF1_B820)
        #expect(d.mnemonic == .addp)
    }

    @Test func reservedAddpNonDoubleSizeReturnsUndefined() {
        let d = decode(0x5EB1_B820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func fmaxnmpScalarSinglePair() {
        let d = decode(0x7E30_C820)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpScalarSinglePair() {
        let d = decode(0x7EB0_C820)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func faddpScalarSinglePair() {
        let d = decode(0x7E30_D820)
        #expect(d.mnemonic == .faddp)
    }

    @Test func fmaxpScalarSinglePair() {
        let d = decode(0x7E30_F820)
        #expect(d.mnemonic == .fmaxp)
    }

    @Test func fminpScalarSinglePair() {
        let d = decode(0x7EB0_F820)
        #expect(d.mnemonic == .fminp)
    }

    @Test func reservedScalarPairwiseReturnsUndefined() {
        let d = decode(0x7E30_8820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func uEqualsZeroNonAddpReturnsUndefined() {
        let d = decode(0x5EF1_C820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar copy.
@Suite("SIMD/FP / AdvSIMD scalar copy")
struct AdvSIMDScalarCopyTests {
    @Test func dupElementScalarByte() {
        let d = decode(0x5E01_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementScalarHalfword() {
        let d = decode(0x5E02_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementScalarWord() {
        let d = decode(0x5E04_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func dupElementScalarDoubleword() {
        let d = decode(0x5E08_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func reservedImm5ZeroReturnsUndefined() {
        let d = decode(0x5E00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpEqualsOneReturnsUndefined() {
        let d = decode(0x7E01_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedImm4NonZeroReturnsUndefined() {
        let d = decode(0x5E01_0C20)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar shift-by-immediate across every shift, narrow,
/// saturating and fixed-point convert row at scalar widths.
@Suite("SIMD/FP / AdvSIMD scalar shift-by-immediate")
struct AdvSIMDScalarShiftByImmediateTests {
    @Test func sshrScalarDouble() {
        let d = decode(0x5F7F_0420)
        #expect(d.mnemonic == .sshr)
    }

    @Test func ssraScalarDouble() {
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
        let d = decode(0x5F41_5420)
        #expect(d.mnemonic == .shl)
    }

    @Test func sqshlScalarDouble() {
        let d = decode(0x5F41_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func sqshrnScalarHalf() {
        let d = decode(0x5F3F_9420)
        #expect(d.mnemonic == .sqshrn)
    }

    @Test func sqrshrnScalarHalf() {
        let d = decode(0x5F3F_9C20)
        #expect(d.mnemonic == .sqrshrn)
    }

    @Test func scvtfScalarFixed() {
        let d = decode(0x5F3F_E420)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func fcvtzsScalarFixed() {
        let d = decode(0x5F3F_FC20)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func ushrScalarDouble() {
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
        let d = decode(0x5F00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedOpcodeReturnsUndefined() {
        let d = decode(0x5F7F_C420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dOnlyOpcodeWithNonDElementReturnsUndefined() {
        let d = decode(0x5F0F_0420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD scalar x-indexed-element.
@Suite("SIMD/FP / AdvSIMD scalar x-indexed-element")
struct AdvSIMDScalarXIndexedElementTests {
    @Test func fmulScalarSingleElement() {
        let d = decode(0x5F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmlaScalarSingleElement() {
        let d = decode(0x5F82_1020)
        #expect(d.mnemonic == .fmla)
    }

    @Test func fmlsScalarSingleElement() {
        let d = decode(0x5F82_5020)
        #expect(d.mnemonic == .fmls)
    }

    @Test func fmulxScalarSingleElement() {
        let d = decode(0x7F82_9020)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func sqdmlalScalarHToS() {
        let d = decode(0x5F42_3020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func sqdmlslScalarHToS() {
        let d = decode(0x5F42_7020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmullScalarHToS() {
        let d = decode(0x5F42_B020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmulhScalarHalf() {
        let d = decode(0x5F42_C020)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhScalarHalf() {
        let d = decode(0x5F42_D020)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func sqrdmlahScalarHalf() {
        let d = decode(0x7F42_D020)
        #expect(d.mnemonic == .sqrdmlah)
    }

    @Test func sqrdmlshScalarHalf() {
        let d = decode(0x7F42_F020)
        #expect(d.mnemonic == .sqrdmlsh)
    }

    @Test func reservedFPOpcodeReturnsUndefined() {
        let d = decode(0x7F82_1020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntSizeReturnsUndefined() {
        let d = decode(0x5F02_3020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        let d = decode(0x5F42_0020)
        #expect(d.mnemonic == .undefined)
    }
}

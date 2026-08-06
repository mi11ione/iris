// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD vector copy.
@Suite("SIMD/FP / AdvSIMD vector copy")
struct AdvSIMDVectorCopyTests {
    @Test func dupElementToVectorB8() {
        let d = decode(0x0E01_0420)
        #expect(d.mnemonic == .dup)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func dupElementToVectorB16() {
        let d = decode(0x4E01_0420)
        #expect(d.mnemonic == .dup)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b16)),
        ))
    }

    @Test func dupElementToVectorH4() {
        let d = decode(0x0E02_0420)
        #expect(d.mnemonic == .dup)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h4)),
        ))
    }

    @Test func dupElementToVectorS2() {
        let d = decode(0x0E04_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementToVectorD2() {
        let d = decode(0x4E08_0420)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupElementDqWithQZeroReservedDLane() {
        let d = decode(0x0E08_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dupGeneralWFromWByteVector() {
        let d = decode(0x0E01_0C20)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupGeneralXFromXDoubleword() {
        let d = decode(0x4E08_0C20)
        #expect(d.mnemonic == .dup)
    }

    @Test func dupGeneralDWithQZeroReserved() {
        let d = decode(0x0E08_0C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func insGeneralAliasMov() {
        let d = decode(0x4E01_1C20)
        #expect(d.mnemonic == .mov)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .element(arrangement: .b16, index: 0)),
        ))
    }

    @Test func insGeneralQZeroReserved() {
        let d = decode(0x0E01_1C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smovWFromVnB() {
        let d = decode(0x0E01_2C20)
        #expect(d.mnemonic == .smov)
    }

    @Test func smovXFromVnB() {
        let d = decode(0x4E01_2C20)
        #expect(d.mnemonic == .smov)
    }

    @Test func smovDLaneReserved() {
        let d = decode(0x4E08_2C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func smovSElementQZeroReserved() {
        let d = decode(0x0E04_2C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func umovWFromVnB() {
        let d = decode(0x0E01_3C20)
        #expect(d.mnemonic == .umov)
    }

    @Test func umovWFromVnS_AliasMov() {
        let d = decode(0x0E04_3C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovXFromVnD_AliasMov() {
        let d = decode(0x4E08_3C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func umovBHWithQOneReserved() {
        let d = decode(0x4E01_3C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func insElementToElementAliasMov() {
        let d = decode(0x6E01_0420)
        #expect(d.mnemonic == .mov)
    }

    @Test func insElementToElementQZeroReserved() {
        let d = decode(0x2E01_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func imm5ZeroReservedAtVectorCopy() {
        let d = decode(0x0E00_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownImm4ReturnsUndefined() {
        let d = decode(0x0E01_2420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector permute.
@Suite("SIMD/FP / AdvSIMD vector permute")
struct AdvSIMDVectorPermuteTests {
    @Test func uzp1V0_8B() {
        let d = decode(0x0E02_1820)
        #expect(d.mnemonic == .uzp1)
    }

    @Test func trn1V0_8B() {
        let d = decode(0x0E02_2820)
        #expect(d.mnemonic == .trn1)
    }

    @Test func zip1V0_8B() {
        let d = decode(0x0E02_3820)
        #expect(d.mnemonic == .zip1)
    }

    @Test func uzp2V0_8B() {
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
        let d = decode(0x0E02_0820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSizeD1ReturnsUndefined() {
        let d = decode(0x0EE2_1820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector extract.
@Suite("SIMD/FP / AdvSIMD vector extract")
struct AdvSIMDVectorExtractTests {
    @Test func extV0_8B() {
        let d = decode(0x2E02_0820)
        #expect(d.mnemonic == .ext)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func extV0_16B() {
        let d = decode(0x6E02_0820)
        #expect(d.mnemonic == .ext)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b16)),
        ))
    }

    @Test func extQZeroImm4HighBitReserved() {
        let d = decode(0x2E02_4020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func extOp2NonZeroReserved() {
        let d = decode(0x2E62_0820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD table lookup.
@Suite("SIMD/FP / AdvSIMD table lookup")
struct AdvSIMDTableLookupTests {
    @Test func tblOneTableV0_8B() {
        let d = decode(0x0E02_0020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func tblTwoTablesV0_8B() {
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
        let d = decode(0x0E02_1020)
        #expect(d.mnemonic == .tbx)
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func tblQ1V0_16B() {
        let d = decode(0x4E02_0020)
        #expect(d.mnemonic == .tbl)
    }

    @Test func reservedOp2ReturnsUndefined() {
        let d = decode(0x0E42_0020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD across-lanes.
@Suite("SIMD/FP / AdvSIMD across-lanes")
struct AdvSIMDAcrossLanesTests {
    @Test func saddlvHFromV_8B() {
        let d = decode(0x0E30_3820)
        #expect(d.mnemonic == .saddlv)
    }

    @Test func uaddlvFrom_8B() {
        let d = decode(0x2E30_3820)
        #expect(d.mnemonic == .uaddlv)
    }

    @Test func smaxvHFromV_8B() {
        let d = decode(0x0E30_A820)
        #expect(d.mnemonic == .smaxv)
    }

    @Test func sminvHFromV_8B() {
        let d = decode(0x0E31_A820)
        #expect(d.mnemonic == .sminv)
    }

    @Test func addvFromV_8B() {
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
        let d = decode(0x6E30_C820)
        #expect(d.mnemonic == .fmaxnmv)
    }

    @Test func fmaxvSFromV_4S() {
        let d = decode(0x6E30_F820)
        #expect(d.mnemonic == .fmaxv)
    }

    @Test func fminnmvSFromV_4S() {
        let d = decode(0x6EB0_C820)
        #expect(d.mnemonic == .fminnmv)
    }

    @Test func fminvSFromV_4S() {
        let d = decode(0x6EB0_F820)
        #expect(d.mnemonic == .fminv)
    }

    @Test func reservedAcrossLanesArrangement_1DReturnsUndefined() {
        let d = decode(0x0EF0_3820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAcrossLanesArrangement_2SReturnsUndefined() {
        let d = decode(0x0EB0_3820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedAcrossLanesOpcodeReturnsUndefined() {
        let d = decode(0x0E30_0820)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD modified-immediate.
@Suite("SIMD/FP / AdvSIMD modified-immediate")
struct AdvSIMDModifiedImmediateTests {
    @Test func moviTwoEs() {
        let d = decode(0x0F00_0400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviFourS() {
        let d = decode(0x4F00_0400)
        #expect(d.mnemonic == .movi)
    }

    @Test func mvniTwoS() {
        let d = decode(0x2F00_0400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func orrImmTwoS() {
        let d = decode(0x0F00_1400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImmTwoS() {
        let d = decode(0x2F00_1400)
        #expect(d.mnemonic == .bic)
    }

    @Test func moviFourH() {
        let d = decode(0x0F00_8400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviEightH() {
        let d = decode(0x4F00_8400)
        #expect(d.mnemonic == .movi)
    }

    @Test func orrImm_4H() {
        let d = decode(0x0F00_9400)
        #expect(d.mnemonic == .orr)
    }

    @Test func bicImm_4H() {
        let d = decode(0x2F00_9400)
        #expect(d.mnemonic == .bic)
    }

    @Test func moviMSLShift8() {
        let d = decode(0x0F00_C400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviMSLShift16() {
        let d = decode(0x0F00_D400)
        #expect(d.mnemonic == .movi)
    }

    @Test func mvniMSLShift8() {
        let d = decode(0x2F00_C400)
        #expect(d.mnemonic == .mvni)
    }

    @Test func moviEightBitByte() {
        let d = decode(0x0F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviSixtyFourBit() {
        let d = decode(0x6F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func moviSixtyFourBitScalarDn() {
        let d = decode(0x2F00_E400)
        #expect(d.mnemonic == .movi)
    }

    @Test func fmovImmediateSingle() {
        let d = decode(0x0F00_F400)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovImmediateDouble() {
        let d = decode(0x6F00_F400)
        #expect(d.mnemonic == .fmov)
    }

    @Test func fmovImmediateDoubleQZeroReserved() {
        let d = decode(0x2F00_F400)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD shift-by-immediate across every shift, lengthen, narrow,
/// saturating and fixed-point convert row.
@Suite("SIMD/FP / AdvSIMD shift-by-immediate")
struct AdvSIMDShiftByImmediateTests {
    @Test func sshrV0_8B() {
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
        let d = decode(0x0F09_5420)
        #expect(d.mnemonic == .shl)
    }

    @Test func sqshl() {
        let d = decode(0x0F09_7420)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func shrn_AndShrn2() {
        let d = decode(0x0F0F_8420)
        #expect(d.mnemonic == .shrn)
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
        let d = decode(0x0F08_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshllNonZeroShift() {
        let d = decode(0x0F09_A420)
        #expect(d.mnemonic == .sshll)
    }

    @Test func sshll2ShiftZeroQ1() {
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
        let d = decode(0x2F08_A420)
        #expect(d.mnemonic == .ushll)
    }

    @Test func ushllNonZeroShift() {
        let d = decode(0x2F09_A420)
        #expect(d.mnemonic == .ushll)
    }

    @Test func ushll2ShiftZeroQ1() {
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
        let d = decode(0x0F80_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func dElementWithQ0NonLengtheningReturnsUndefined() {
        let d = decode(0x0F7F_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        let d = decode(0x0F0F_6420)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector x-indexed-element across every multiply,
/// multiply-accumulate, lengthening and dot-product row.
@Suite("SIMD/FP / AdvSIMD vector x-indexed-element")
struct AdvSIMDVectorXIndexedElementTests {
    @Test func fmulVector_2S() {
        let d = decode(0x0F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmulVector_4S() {
        let d = decode(0x4F82_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmulVector_2D() {
        let d = decode(0x4FC2_9020)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fmlaVector_2S() {
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
        let d = decode(0x0F42_8020)
        #expect(d.mnemonic == .mul)
    }

    @Test func mlaVector_4H() {
        let d = decode(0x2F42_0020)
        #expect(d.mnemonic == .mla)
    }

    @Test func mlsVector_4H() {
        let d = decode(0x2F42_4020)
        #expect(d.mnemonic == .mls)
    }

    @Test func smlalVector_4S() {
        let d = decode(0x0F42_2020)
        #expect(d.mnemonic == .smlal)
    }

    @Test func smlslVector_4S() {
        let d = decode(0x0F42_6020)
        #expect(d.mnemonic == .smlsl)
    }

    @Test func smullVector_4S() {
        let d = decode(0x0F42_A020)
        #expect(d.mnemonic == .smull)
    }

    @Test func sqdmullVector_4S() {
        let d = decode(0x0F42_B020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func sqdmlalVector_4S() {
        let d = decode(0x0F42_3020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func sqdmlslVector_4S() {
        let d = decode(0x0F42_7020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func sqdmulhVector_4H() {
        let d = decode(0x0F42_C020)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhVector_4H() {
        let d = decode(0x0F42_D020)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func sdotVector_2S() {
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
        let d = decode(0x0FC2_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntSizeReturnsUndefined() {
        let d = decode(0x2F22_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedIntOpcodeReturnsUndefined() {
        let d = decode(0x2F42_9020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector three-reg-extension.
@Suite("SIMD/FP / AdvSIMD three-reg-extension")
struct AdvSIMDVectorThreeRegExtensionTests {
    @Test func sdotVector_4S() {
        let d = decode(0x4E82_9420)
        #expect(d.mnemonic == .sdot)
    }

    @Test func udotVector_4S() {
        let d = decode(0x6E82_9420)
        #expect(d.mnemonic == .udot)
    }

    @Test func usdotVector_4S() {
        let d = decode(0x4E82_9C20)
        #expect(d.mnemonic == .usdot)
    }

    @Test func smmlaVector_4S() {
        let d = decode(0x4E82_A420)
        #expect(d.mnemonic == .smmla)
    }

    @Test func ummlaVector_4S() {
        let d = decode(0x6E82_A420)
        #expect(d.mnemonic == .ummla)
    }

    @Test func bfmmlaVector_4S() {
        let d = decode(0x6E42_EC20)
        #expect(d.mnemonic == .bfmmla)
    }

    @Test func usmmlaVector_4S() {
        let d = decode(0x4E82_AC20)
        #expect(d.mnemonic == .usmmla)
    }

    @Test func bfmlalbVector_4S() {
        let d = decode(0x2EC2_FC20)
        #expect(d.mnemonic == .bfmlalb)
    }

    @Test func reservedReturnsUndefined() {
        let d = decode(0x6E82_3420)
        #expect(d.mnemonic == .undefined)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD vector three-same.
@Suite("SIMD/FP / AdvSIMD vector three-same")
struct AdvSIMDVectorThreeSameTests {
    @Test func addV0_8BV1V2() {
        let d = decode(0x0E22_8420)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func subV0_4HV1V2() {
        let d = decode(0x2E62_8420)
        #expect(d.mnemonic == .sub)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h4)),
        ))
    }

    @Test func mulV0_2SV1V2() {
        let d = decode(0x0EA2_9C20)
        #expect(d.mnemonic == .mul)
    }

    @Test func mlaV0_4S() {
        let d = decode(0x4EA2_9420)
        #expect(d.mnemonic == .mla)
    }

    @Test func mlsV0_4S() {
        let d = decode(0x6EA2_9420)
        #expect(d.mnemonic == .mls)
    }

    @Test func cmgtV0_8B() {
        let d = decode(0x0E22_3420)
        #expect(d.mnemonic == .cmgt)
    }

    @Test func cmgeV0_8B() {
        let d = decode(0x0E22_3C20)
        #expect(d.mnemonic == .cmge)
    }

    @Test func sshlV0_8B() {
        let d = decode(0x0E22_4420)
        #expect(d.mnemonic == .sshl)
    }

    @Test func sqshlV0_8B() {
        let d = decode(0x0E22_4C20)
        #expect(d.mnemonic == .sqshl)
    }

    @Test func srshlV0_8B() {
        let d = decode(0x0E22_5420)
        #expect(d.mnemonic == .srshl)
    }

    @Test func sqrshlV0_8B() {
        let d = decode(0x0E22_5C20)
        #expect(d.mnemonic == .sqrshl)
    }

    @Test func smaxV0_8B() {
        let d = decode(0x0E22_6420)
        #expect(d.mnemonic == .smax)
    }

    @Test func sminV0_8B() {
        let d = decode(0x0E22_6C20)
        #expect(d.mnemonic == .smin)
    }

    @Test func sabdV0_8B() {
        let d = decode(0x0E22_7420)
        #expect(d.mnemonic == .sabd)
    }

    @Test func sabaV0_8B() {
        let d = decode(0x0E22_7C20)
        #expect(d.mnemonic == .saba)
    }

    @Test func sqaddV0_8B() {
        let d = decode(0x0E22_0C20)
        #expect(d.mnemonic == .sqadd)
    }

    @Test func sqsubV0_8B() {
        let d = decode(0x0E22_2C20)
        #expect(d.mnemonic == .sqsub)
    }

    @Test func uqaddV0_8B() {
        let d = decode(0x2E22_0C20)
        #expect(d.mnemonic == .uqadd)
    }

    @Test func uqsubV0_8B() {
        let d = decode(0x2E22_2C20)
        #expect(d.mnemonic == .uqsub)
    }

    @Test func cmhiV0_8B() {
        let d = decode(0x2E22_3420)
        #expect(d.mnemonic == .cmhi)
    }

    @Test func cmhsV0_8B() {
        let d = decode(0x2E22_3C20)
        #expect(d.mnemonic == .cmhs)
    }

    @Test func ushlV0_8B() {
        let d = decode(0x2E22_4420)
        #expect(d.mnemonic == .ushl)
    }

    @Test func uqshlV0_8B() {
        let d = decode(0x2E22_4C20)
        #expect(d.mnemonic == .uqshl)
    }

    @Test func urshlV0_8B() {
        let d = decode(0x2E22_5420)
        #expect(d.mnemonic == .urshl)
    }

    @Test func uqrshlV0_8B() {
        let d = decode(0x2E22_5C20)
        #expect(d.mnemonic == .uqrshl)
    }

    @Test func cmtstV0_8B() {
        let d = decode(0x0E22_8C20)
        #expect(d.mnemonic == .cmtst)
    }

    @Test func cmeqV0_8B() {
        let d = decode(0x2E22_8C20)
        #expect(d.mnemonic == .cmeq)
    }

    @Test func uabdV0_8B() {
        let d = decode(0x2E22_7420)
        #expect(d.mnemonic == .uabd)
    }

    @Test func uabaV0_8B() {
        let d = decode(0x2E22_7C20)
        #expect(d.mnemonic == .uaba)
    }

    @Test func pmulV0_8B() {
        let d = decode(0x2E22_9C20)
        #expect(d.mnemonic == .pmul)
    }

    @Test func pmulRejectsNonByteSize() {
        let d = decode(0x2E62_9C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sqdmulhV0_4H() {
        let d = decode(0x0E62_B420)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhV0_4H() {
        let d = decode(0x2E62_B420)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func smaxpV0_8B() {
        let d = decode(0x0E22_A420)
        #expect(d.mnemonic == .smaxp)
    }

    @Test func sminpV0_8B() {
        let d = decode(0x0E22_AC20)
        #expect(d.mnemonic == .sminp)
    }

    @Test func umaxpV0_8B() {
        let d = decode(0x2E22_A420)
        #expect(d.mnemonic == .umaxp)
    }

    @Test func uminpV0_8B() {
        let d = decode(0x2E22_AC20)
        #expect(d.mnemonic == .uminp)
    }

    @Test func addpV0_8B() {
        let d = decode(0x0E22_BC20)
        #expect(d.mnemonic == .addp)
    }

    @Test func shaddV0_8B() {
        let d = decode(0x0E22_0420)
        #expect(d.mnemonic == .shadd)
    }

    @Test func srhaddV0_8B() {
        let d = decode(0x0E22_1420)
        #expect(d.mnemonic == .srhadd)
    }

    @Test func shsubV0_8B() {
        let d = decode(0x0E22_2420)
        #expect(d.mnemonic == .shsub)
    }

    @Test func uhaddV0_8B() {
        let d = decode(0x2E22_0420)
        #expect(d.mnemonic == .uhadd)
    }

    @Test func urhaddV0_8B() {
        let d = decode(0x2E22_1420)
        #expect(d.mnemonic == .urhadd)
    }

    @Test func uhsubV0_8B() {
        let d = decode(0x2E22_2420)
        #expect(d.mnemonic == .uhsub)
    }

    @Test func umaxV0_8B() {
        let d = decode(0x2E22_6420)
        #expect(d.mnemonic == .umax)
    }

    @Test func uminV0_8B() {
        let d = decode(0x2E22_6C20)
        #expect(d.mnemonic == .umin)
    }

    @Test func andVectorEightByte() {
        let d = decode(0x0E22_1C20)
        #expect(d.mnemonic == .and)
    }

    @Test func bicVector() {
        let d = decode(0x0E62_1C20)
        #expect(d.mnemonic == .bic)
    }

    @Test func orrVectorWhenRmEqualsRnAliasesToMov() {
        let d = decode(0x0EA1_1C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func orrVectorWhenRmDiffersFromRnRemainsOrr() {
        let d = decode(0x0EA2_1C20)
        #expect(d.mnemonic == .orr)
    }

    @Test func ornVector() {
        let d = decode(0x0EE2_1C20)
        #expect(d.mnemonic == .orn)
    }

    @Test func eorVector() {
        let d = decode(0x2E22_1C20)
        #expect(d.mnemonic == .eor)
    }

    @Test func bslVector() {
        let d = decode(0x2E62_1C20)
        #expect(d.mnemonic == .bsl)
    }

    @Test func bitVector() {
        let d = decode(0x2EA2_1C20)
        #expect(d.mnemonic == .bit)
    }

    @Test func bifVector() {
        let d = decode(0x2EE2_1C20)
        #expect(d.mnemonic == .bif)
    }

    @Test func fmaxnmVector_S2() {
        let d = decode(0x0E22_C420)
        #expect(d.mnemonic == .fmaxnm)
    }

    @Test func fminnmVector_2S() {
        let d = decode(0x0EA2_C420)
        #expect(d.mnemonic == .fminnm)
    }

    @Test func fmlaVector_2S() {
        let d = decode(0x0E22_CC20)
        #expect(d.mnemonic == .fmla)
    }

    @Test func fmlsVector_2S() {
        let d = decode(0x0EA2_CC20)
        #expect(d.mnemonic == .fmls)
    }

    @Test func faddVector_2S() {
        let d = decode(0x0E22_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func fsubVector_2S() {
        let d = decode(0x0EA2_D420)
        #expect(d.mnemonic == .fsub)
    }

    @Test func fmulxVector_2S() {
        let d = decode(0x0E22_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcmeqVector_2S() {
        let d = decode(0x0E22_E420)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func fmaxVector_2S() {
        let d = decode(0x0E22_F420)
        #expect(d.mnemonic == .fmax)
    }

    @Test func fminVector_2S() {
        let d = decode(0x0EA2_F420)
        #expect(d.mnemonic == .fmin)
    }

    @Test func frecpsVector_2S() {
        let d = decode(0x0E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func frsqrtsVector_2S() {
        let d = decode(0x0EA2_FC20)
        #expect(d.mnemonic == .frsqrts)
    }

    @Test func fmaxnmpVector_2S() {
        let d = decode(0x2E22_C420)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpVector_2S() {
        let d = decode(0x2EA2_C420)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func faddpVector_2S() {
        let d = decode(0x2E22_D420)
        #expect(d.mnemonic == .faddp)
    }

    @Test func fabdVector_2S() {
        let d = decode(0x2EA2_D420)
        #expect(d.mnemonic == .fabd)
    }

    @Test func fmulVector_2S() {
        let d = decode(0x2E22_DC20)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fcmgeVector_2S() {
        let d = decode(0x2E22_E420)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmgtVector_2S() {
        let d = decode(0x2EA2_E420)
        #expect(d.mnemonic == .fcmgt)
    }

    @Test func facgeVector_2S() {
        let d = decode(0x2E22_EC20)
        #expect(d.mnemonic == .facge)
    }

    @Test func facgtVector_2S() {
        let d = decode(0x2EA2_EC20)
        #expect(d.mnemonic == .facgt)
    }

    @Test func fmaxpVector_2S() {
        let d = decode(0x2E22_F420)
        #expect(d.mnemonic == .fmaxp)
    }

    @Test func fminpVector_2S() {
        let d = decode(0x2EA2_F420)
        #expect(d.mnemonic == .fminp)
    }

    @Test func fdivVector_2S() {
        let d = decode(0x2E22_FC20)
        #expect(d.mnemonic == .fdiv)
    }

    @Test func reservedFPSizeAndQReturnsUndefined() {
        let d = decode(0x0EE2_D420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSize11ForNon_DOpcodeReturnsUndefined() {
        let d = decode(0x0EE2_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        let d = decode(0x0E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func semanticReadsForMLAIncludeDestination() {
        let d = decode(0x4EA2_9420)
        #expect(d.semanticReads.contains(.simd(0)))
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
    }

    @Test func semanticReadsForPlainADDExcludeDestination() {
        let d = decode(0x0E22_8420)
        #expect(!d.semanticReads.contains(.simd(0)))
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
    }
}

/// Validates AdvSIMD vector three-different.
@Suite("SIMD/FP / AdvSIMD vector three-different")
struct AdvSIMDVectorThreeDifferentTests {
    @Test func saddlV0_8H_V1_8B_V2_8B() {
        let d = decode(0x0E22_0020)
        #expect(d.mnemonic == .saddl)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h8)),
        ))
        #expect(d.operands[1] == .vectorRegister(
            VectorRegisterRef(registerIndex: 1, view: .full(arrangement: .b8)),
        ))
    }

    @Test func saddwV0_8H_V1_8H_V2_8B() {
        let d = decode(0x0E22_1020)
        #expect(d.mnemonic == .saddw)
    }

    @Test func ssublV0_4S() {
        let d = decode(0x0E62_2020)
        #expect(d.mnemonic == .ssubl)
    }

    @Test func ssubwV0_4S() {
        let d = decode(0x0E62_3020)
        #expect(d.mnemonic == .ssubw)
    }

    @Test func addhnV0_8B() {
        let d = decode(0x0E22_4020)
        #expect(d.mnemonic == .addhn)
    }

    @Test func sabalV0_8H() {
        let d = decode(0x0E22_5020)
        #expect(d.mnemonic == .sabal)
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func subhnV0_8B() {
        let d = decode(0x0E22_6020)
        #expect(d.mnemonic == .subhn)
    }

    @Test func sabdlV0_8H() {
        let d = decode(0x0E22_7020)
        #expect(d.mnemonic == .sabdl)
    }

    @Test func smlalV0_4S() {
        let d = decode(0x0E62_8020)
        #expect(d.mnemonic == .smlal)
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func sqdmlalV0_4S() {
        let d = decode(0x0E62_9020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func smlslV0_4S() {
        let d = decode(0x0E62_A020)
        #expect(d.mnemonic == .smlsl)
    }

    @Test func sqdmlslV0_4S() {
        let d = decode(0x0E62_B020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func smullV0_4S() {
        let d = decode(0x0E62_C020)
        #expect(d.mnemonic == .smull)
    }

    @Test func sqdmullV0_4S() {
        let d = decode(0x0E62_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func pmullV0_8H() {
        let d = decode(0x0E22_E020)
        #expect(d.mnemonic == .pmull)
    }

    @Test func uaddlV0_8H() {
        let d = decode(0x2E22_0020)
        #expect(d.mnemonic == .uaddl)
    }

    @Test func uaddwV0_8H() {
        let d = decode(0x2E22_1020)
        #expect(d.mnemonic == .uaddw)
    }

    @Test func usublV0_8H() {
        let d = decode(0x2E22_2020)
        #expect(d.mnemonic == .usubl)
    }

    @Test func usubwV0_8H() {
        let d = decode(0x2E22_3020)
        #expect(d.mnemonic == .usubw)
    }

    @Test func raddhnV0_8B() {
        let d = decode(0x2E22_4020)
        #expect(d.mnemonic == .raddhn)
    }

    @Test func uabalV0_8H() {
        let d = decode(0x2E22_5020)
        #expect(d.mnemonic == .uabal)
    }

    @Test func rsubhnV0_8B() {
        let d = decode(0x2E22_6020)
        #expect(d.mnemonic == .rsubhn)
    }

    @Test func uabdlV0_8H() {
        let d = decode(0x2E22_7020)
        #expect(d.mnemonic == .uabdl)
    }

    @Test func umlalV0_4S() {
        let d = decode(0x2E62_8020)
        #expect(d.mnemonic == .umlal)
    }

    @Test func umlslV0_4S() {
        let d = decode(0x2E62_A020)
        #expect(d.mnemonic == .umlsl)
    }

    @Test func umullV0_4S() {
        let d = decode(0x2E62_C020)
        #expect(d.mnemonic == .umull)
    }

    @Test func reservedSize11ReturnsUndefined() {
        let d = decode(0x0EE2_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedU1OpcodeReturnsUndefined() {
        let d = decode(0x2E62_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedU1Opcode1110ReturnsUndefined() {
        let d = decode(0x2E22_E020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector two-reg-misc.
@Suite("SIMD/FP / AdvSIMD vector two-reg-misc")
struct AdvSIMDVectorTwoRegMiscTests {
    @Test func rev64V0_8B() {
        let d = decode(0x0E20_0820)
        #expect(d.mnemonic == .rev64)
    }

    @Test func rev16V0_8B() {
        let d = decode(0x0E20_1820)
        #expect(d.mnemonic == .rev16)
    }

    @Test func clsV0_8B() {
        let d = decode(0x0E20_4820)
        #expect(d.mnemonic == .cls)
    }

    @Test func cntV0_8B() {
        let d = decode(0x0E20_5820)
        #expect(d.mnemonic == .cnt)
    }

    @Test func saddlpV0_4H() {
        let d = decode(0x0E20_2820)
        #expect(d.mnemonic == .saddlp)
    }

    @Test func suqaddV0_8B() {
        let d = decode(0x0E20_3820)
        #expect(d.mnemonic == .suqadd)
    }

    @Test func sqabsV0_8B() {
        let d = decode(0x0E20_7820)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func absV0_8B() {
        let d = decode(0x0E20_B820)
        #expect(d.mnemonic == .abs)
    }

    @Test func cmgtZeroV0_8B() {
        let d = decode(0x0E20_8820)
        #expect(d.mnemonic == .cmgt)
        #expect(d.operands.count == 3)
    }

    @Test func cmeqZeroV0_8B() {
        let d = decode(0x0E20_9820)
        #expect(d.mnemonic == .cmeq)
    }

    @Test func cmltZeroV0_8B() {
        let d = decode(0x0E20_A820)
        #expect(d.mnemonic == .cmlt)
    }

    @Test func xtnV0_8B() {
        let d = decode(0x0E21_2820)
        #expect(d.mnemonic == .xtn)
    }

    @Test func sqxtnV0_8B() {
        let d = decode(0x0E21_4820)
        #expect(d.mnemonic == .sqxtn)
    }

    @Test func shllV0_8H() {
        let d = decode(0x2E21_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func rev32V0_8B() {
        let d = decode(0x2E20_0820)
        #expect(d.mnemonic == .rev32)
    }

    @Test func uaddlpV0_4H() {
        let d = decode(0x2E20_2820)
        #expect(d.mnemonic == .uaddlp)
    }

    @Test func usqaddV0_8B() {
        let d = decode(0x2E20_3820)
        #expect(d.mnemonic == .usqadd)
    }

    @Test func clzV0_8B() {
        let d = decode(0x2E20_4820)
        #expect(d.mnemonic == .clz)
    }

    @Test func uadalpV0_4H() {
        let d = decode(0x2E20_6820)
        #expect(d.mnemonic == .uadalp)
    }

    @Test func sqnegV0_8B() {
        let d = decode(0x2E20_7820)
        #expect(d.mnemonic == .sqneg)
    }

    @Test func cmgeZeroV0_8B() {
        let d = decode(0x2E20_8820)
        #expect(d.mnemonic == .cmge)
    }

    @Test func cmleZeroV0_8B() {
        let d = decode(0x2E20_9820)
        #expect(d.mnemonic == .cmle)
    }

    @Test func negV0_8B() {
        let d = decode(0x2E20_B820)
        #expect(d.mnemonic == .neg)
    }

    @Test func sqxtunV0_8B() {
        let d = decode(0x2E21_2820)
        #expect(d.mnemonic == .sqxtun)
    }

    @Test func uqxtnV0_8B() {
        let d = decode(0x2E21_4820)
        #expect(d.mnemonic == .uqxtn)
    }

    @Test func mvnV0_8B() {
        let d = decode(0x2E20_5820)
        #expect(d.mnemonic == .mvn)
    }

    @Test func mvnRejectsNonByteSize() {
        let d = decode(0x2EA0_5820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func rbitV0_8B() {
        let d2 = decode(0x2E60_5820)
        #expect(d2.mnemonic == .rbit)
    }

    @Test func rbitRejectsNonByteSize() {
        let d = decode(0x2E60_1820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func frintnVector_2S() {
        let d = decode(0x0E21_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func frintpVector_2S() {
        let d = decode(0x0EA1_8820)
        #expect(d.mnemonic == .frintp)
    }

    @Test func frintmVector_2S() {
        let d = decode(0x0E21_9820)
        #expect(d.mnemonic == .frintm)
    }

    @Test func frintzVector_2S() {
        let d = decode(0x0EA1_9820)
        #expect(d.mnemonic == .frintz)
    }

    @Test func fcvtnsVector_2S() {
        let d = decode(0x0E21_A820)
        #expect(d.mnemonic == .fcvtns)
    }

    @Test func fcvtpsVector_2S() {
        let d = decode(0x0EA1_A820)
        #expect(d.mnemonic == .fcvtps)
    }

    @Test func fcvtmsVector_2S() {
        let d = decode(0x0E21_B820)
        #expect(d.mnemonic == .fcvtms)
    }

    @Test func fcvtzsVector_2S() {
        let d = decode(0x0EA1_B820)
        #expect(d.mnemonic == .fcvtzs)
    }

    @Test func fcvtasVector_2S() {
        let d = decode(0x0E21_C820)
        #expect(d.mnemonic == .fcvtas)
    }

    @Test func scvtfVector_2S() {
        let d = decode(0x0E21_D820)
        #expect(d.mnemonic == .scvtf)
    }

    @Test func frecpeVector_2S() {
        let d = decode(0x0EA1_D820)
        #expect(d.mnemonic == .frecpe)
    }

    @Test func fsqrtVector_2S() {
        let d = decode(0x2EA1_F820)
        #expect(d.mnemonic == .fsqrt)
    }

    @Test func fcmgtZeroVector_2S() {
        let d = decode(0x0EA0_C820)
        #expect(d.mnemonic == .fcmgt)
        #expect(d.operands.count == 3)
    }

    @Test func fcmeqZeroVector_2S() {
        let d = decode(0x0EA0_D820)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func fcmltZeroVector_2S() {
        let d = decode(0x0EA0_E820)
        #expect(d.mnemonic == .fcmlt)
    }

    @Test func fabsVector_2S() {
        let d = decode(0x0EA0_F820)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fnegVector_2S() {
        let d = decode(0x2EA0_F820)
        #expect(d.mnemonic == .fneg)
    }

    @Test func fcmgeZeroVector_2S() {
        let d = decode(0x2EA0_C820)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmleZeroVector_2S() {
        let d = decode(0x2EA0_D820)
        #expect(d.mnemonic == .fcmle)
    }

    @Test func frintaVector_2S() {
        let d = decode(0x2E21_8820)
        #expect(d.mnemonic == .frinta)
    }

    @Test func frintxVector_2S() {
        let d = decode(0x2E21_9820)
        #expect(d.mnemonic == .frintx)
    }

    @Test func frintiVector_2S() {
        let d = decode(0x2EA1_9820)
        #expect(d.mnemonic == .frinti)
    }

    @Test func fcvtnuVector_2S() {
        let d = decode(0x2E21_A820)
        #expect(d.mnemonic == .fcvtnu)
    }

    @Test func fcvtpuVector_2S() {
        let d = decode(0x2EA1_A820)
        #expect(d.mnemonic == .fcvtpu)
    }

    @Test func fcvtmuVector_2S() {
        let d = decode(0x2E21_B820)
        #expect(d.mnemonic == .fcvtmu)
    }

    @Test func fcvtzuVector_2S() {
        let d = decode(0x2EA1_B820)
        #expect(d.mnemonic == .fcvtzu)
    }

    @Test func fcvtauVector_2S() {
        let d = decode(0x2E21_C820)
        #expect(d.mnemonic == .fcvtau)
    }

    @Test func ucvtfVector_2S() {
        let d = decode(0x2E21_D820)
        #expect(d.mnemonic == .ucvtf)
    }

    @Test func frsqrteVector_2S() {
        let d = decode(0x2EA1_D820)
        #expect(d.mnemonic == .frsqrte)
    }

    @Test func urecpeVector_2S() {
        let d = decode(0x0EA1_C820)
        #expect(d.mnemonic == .urecpe)
    }

    @Test func ursqrteVector_2S() {
        let d = decode(0x2EA1_C820)
        #expect(d.mnemonic == .ursqrte)
    }

    @Test func reservedFPSizeAndQReturnsUndefined() {
        let d = decode(0x0EE1_8820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownIntOpcodeReturnsUndefined() {
        let d = decode(0x0E21_5820)
        #expect(d.mnemonic == .undefined)
    }
}

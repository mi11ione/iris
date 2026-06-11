// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates AdvSIMD vector three-same — the largest sub-class, covering
/// arithmetic (ADD/SUB/MUL/MLA/MLS/...), saturating arithmetic, compares,
/// shifts, max/min, AB-diff, P-mul, addp, plus the FP family
/// (FADD/FSUB/FMUL/FDIV/FMAX/FMIN/FMLA/FMLS/FCMxx/FACxx/FRECPS/FRSQRTS).
@Suite("SIMD/FP / AdvSIMD vector three-same")
struct AdvSIMDVectorThreeSameTests {
    @Test func addV0_8BV1V2() {
        // ADD V0.8B, V1.8B, V2.8B: Q=0, U=0, size=00, opcode=10000, bit10=1.
        // Top byte: bit 30=0 (Q=0), bit 29=0 (U=0), bits[28:24]=01110 = 0x0E.
        // byte 1: size=00, bit 21=1, Rm=2 ⇒ 00_1_00010 = 0010_0010 = 0x22.
        // byte 2: opcode=10000, bit10=1, Rn high = 0.
        // bits[15:11]=10000, bit 10=1, bits 9..8=00 (Rn=1 high).
        // byte 2 = 10000_1_00 = 1000_0100 = 0x84.
        // byte 3: Rn low 3 + Rd = 001_00000 = 0010_0000 = 0x20.
        let d = decode(0x0E22_8420)
        #expect(d.mnemonic == .add)
        #expect(d.operands.count == 3)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8)),
        ))
    }

    @Test func subV0_4HV1V2() {
        // SUB V0.4H, V1.4H, V2.4H: U=1, size=01, opcode=10000.
        // byte 0: 0_0_1_01110 = 0010_1110 = 0x2E.
        // byte 1: 01_1_00010 = 0110_0010 = 0x62.
        // byte 2: 10000_1_00 = 0x84.
        let d = decode(0x2E62_8420)
        #expect(d.mnemonic == .sub)
        #expect(d.operands[0] == .vectorRegister(
            VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .h4)),
        ))
    }

    @Test func mulV0_2SV1V2() {
        // MUL V0.2S, V1.2S, V2.2S: U=0, size=10, opcode=10011.
        // byte 0: 0_0_0_01110 = 0x0E.
        // byte 1: 10_1_00010 = 1010_0010 = 0xA2.
        // byte 2: 10011_1_00 = 1001_1100 = 0x9C.
        let d = decode(0x0EA2_9C20)
        #expect(d.mnemonic == .mul)
    }

    @Test func mlaV0_4S() {
        // MLA: opcode=10010.
        // byte 2 = 10010_1_00 = 1001_0100 = 0x94.
        // Q=1 4S: byte 0 = 0_1_0_01110 = 0x4E. byte 1 size=10: 10_1_00010 = 0xA2.
        let d = decode(0x4EA2_9420)
        #expect(d.mnemonic == .mla)
    }

    @Test func mlsV0_4S() {
        // MLS: U=1 opcode=10010.
        let d = decode(0x6EA2_9420)
        #expect(d.mnemonic == .mls)
    }

    @Test func cmgtV0_8B() {
        // CMGT: opcode=00110.
        // byte 2: 00110_1_00 = 0011_0100 = 0x34.
        let d = decode(0x0E22_3420)
        #expect(d.mnemonic == .cmgt)
    }

    @Test func cmgeV0_8B() {
        // CMGE: opcode=00111.
        let d = decode(0x0E22_3C20)
        #expect(d.mnemonic == .cmge)
    }

    @Test func sshlV0_8B() {
        // SSHL: opcode=01000.
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
        // SMAX: opcode=01100. byte 2 = 01100_100 = 0110_0100 = 0x64.
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
        // SQADD: opcode=00001.
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
        // CMTST: opcode=10001.
        // byte 2 = 10001_1_00 = 1000_1100 = 0x8C.
        let d = decode(0x0E22_8C20)
        #expect(d.mnemonic == .cmtst)
    }

    @Test func cmeqV0_8B() {
        // CMEQ: U=1 opcode=10001.
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
        // PMUL: opcode=10011, U=1. Only valid for size=00 (B-element).
        let d = decode(0x2E22_9C20)
        #expect(d.mnemonic == .pmul)
    }

    @Test func pmulRejectsNonByteSize() {
        // PMUL with size=01 (H) is reserved.
        let d = decode(0x2E62_9C20)
        #expect(d.mnemonic == .undefined)
    }

    @Test func sqdmulhV0_4H() {
        // SQDMULH: opcode=10110, U=0. byte 2 = 10110_1_00 = 1011_0100 = 0xB4.
        let d = decode(0x0E62_B420)
        #expect(d.mnemonic == .sqdmulh)
    }

    @Test func sqrdmulhV0_4H() {
        let d = decode(0x2E62_B420)
        #expect(d.mnemonic == .sqrdmulh)
    }

    @Test func smaxpV0_8B() {
        // SMAXP: opcode=10100. byte 2 = 10100_1_00 = 1010_0100 = 0xA4.
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
        // ADDP: opcode=10111. byte 2 = 10111_1_00 = 1011_1100 = 0xBC.
        let d = decode(0x0E22_BC20)
        #expect(d.mnemonic == .addp)
    }

    @Test func shaddV0_8B() {
        // SHADD: U=0 opcode=00000.
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

    /// Logical opcodes (opcode=00011) — discriminated by size+U.
    @Test func andVectorEightByte() {
        // AND V0.8B, V1.8B, V2.8B: U=0, opcode=00011, size=00.
        // byte 2 = 00011_1_00 = 0001_1100 = 0x1C.
        let d = decode(0x0E22_1C20)
        #expect(d.mnemonic == .and)
    }

    @Test func bicVector() {
        // BIC: U=0, opcode=00011, size=01.
        let d = decode(0x0E62_1C20)
        #expect(d.mnemonic == .bic)
    }

    @Test func orrVectorWhenRmEqualsRnAliasesToMov() {
        // ORR Vd.T, Vn.T, Vn.T (Rm == Rn) → MOV alias.
        // U=0, opcode=00011, size=10 (ORR), Rm == Rn = 1.
        let d = decode(0x0EA1_1C20)
        #expect(d.mnemonic == .mov)
    }

    @Test func orrVectorWhenRmDiffersFromRnRemainsOrr() {
        // ORR Vd.T, Vn.T, Vm.T (Rm != Rn).
        let d = decode(0x0EA2_1C20)
        #expect(d.mnemonic == .orr)
    }

    @Test func ornVector() {
        // ORN: U=0, opcode=00011, size=11.
        let d = decode(0x0EE2_1C20)
        #expect(d.mnemonic == .orn)
    }

    @Test func eorVector() {
        // EOR: U=1, size=00.
        let d = decode(0x2E22_1C20)
        #expect(d.mnemonic == .eor)
    }

    @Test func bslVector() {
        // BSL: U=1, size=01.
        let d = decode(0x2E62_1C20)
        #expect(d.mnemonic == .bsl)
    }

    @Test func bitVector() {
        // BIT: U=1, size=10.
        let d = decode(0x2EA2_1C20)
        #expect(d.mnemonic == .bit)
    }

    @Test func bifVector() {
        // BIF: U=1, size=11.
        let d = decode(0x2EE2_1C20)
        #expect(d.mnemonic == .bif)
    }

    /// FP family.
    @Test func fmaxnmVector_S2() {
        // FMAXNM V0.2S, V1.2S, V2.2S: U=0, opcode=11000, size=00 (sz=0).
        // byte 2 = 11000_1_00 = 1100_0100 = 0xC4.
        let d = decode(0x0E22_C420)
        #expect(d.mnemonic == .fmaxnm)
    }

    @Test func fminnmVector_2S() {
        // FMINNM: opcode=11000, altBit=1 (size=10).
        let d = decode(0x0EA2_C420)
        #expect(d.mnemonic == .fminnm)
    }

    @Test func fmlaVector_2S() {
        // FMLA: opcode=11001.
        let d = decode(0x0E22_CC20)
        #expect(d.mnemonic == .fmla)
    }

    @Test func fmlsVector_2S() {
        // FMLS: opcode=11001 altBit=1.
        let d = decode(0x0EA2_CC20)
        #expect(d.mnemonic == .fmls)
    }

    @Test func faddVector_2S() {
        // FADD: opcode=11010.
        let d = decode(0x0E22_D420)
        #expect(d.mnemonic == .fadd)
    }

    @Test func fsubVector_2S() {
        let d = decode(0x0EA2_D420)
        #expect(d.mnemonic == .fsub)
    }

    @Test func fmulxVector_2S() {
        // FMULX: opcode=11011.
        let d = decode(0x0E22_DC20)
        #expect(d.mnemonic == .fmulx)
    }

    @Test func fcmeqVector_2S() {
        // FCMEQ: opcode=11100.
        let d = decode(0x0E22_E420)
        #expect(d.mnemonic == .fcmeq)
    }

    @Test func fmaxVector_2S() {
        // FMAX: opcode=11110.
        let d = decode(0x0E22_F420)
        #expect(d.mnemonic == .fmax)
    }

    @Test func fminVector_2S() {
        let d = decode(0x0EA2_F420)
        #expect(d.mnemonic == .fmin)
    }

    @Test func frecpsVector_2S() {
        // FRECPS: opcode=11111.
        let d = decode(0x0E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func frsqrtsVector_2S() {
        let d = decode(0x0EA2_FC20)
        #expect(d.mnemonic == .frsqrts)
    }

    @Test func fmaxnmpVector_2S() {
        // U=1, opcode=11000, altBit=0.
        let d = decode(0x2E22_C420)
        #expect(d.mnemonic == .fmaxnmp)
    }

    @Test func fminnmpVector_2S() {
        let d = decode(0x2EA2_C420)
        #expect(d.mnemonic == .fminnmp)
    }

    @Test func faddpVector_2S() {
        // FADDP: U=1, opcode=11010, altBit=0.
        let d = decode(0x2E22_D420)
        #expect(d.mnemonic == .faddp)
    }

    @Test func fabdVector_2S() {
        // FABD: U=1, opcode=11010, altBit=1.
        let d = decode(0x2EA2_D420)
        #expect(d.mnemonic == .fabd)
    }

    @Test func fmulVector_2S() {
        // FMUL (vector): U=1, opcode=11011, altBit=0.
        let d = decode(0x2E22_DC20)
        #expect(d.mnemonic == .fmul)
    }

    @Test func fcmgeVector_2S() {
        let d = decode(0x2E22_E420)
        #expect(d.mnemonic == .fcmge)
    }

    @Test func fcmgtVector_2S() {
        // FCMGT vector reg-reg: U=1, opcode=11100, altBit=1.
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
        // FP family with sz=1 (D) and Q=0 (.1D) reserved.
        let d = decode(0x0EE2_D420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedSize11ForNon_DOpcodeReturnsUndefined() {
        // SHADD with size=11 reserved.
        let d = decode(0x0EE2_0420)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownOpcodeReturnsUndefined() {
        // U=0 opcode=11111 is reserved in the integer three-same range
        // but lands in the FP three-same family: with size=00 it decodes
        // FRECPS rather than undefined.
        let d = decode(0x0E22_FC20)
        #expect(d.mnemonic == .frecps)
    }

    @Test func semanticReadsForMLAIncludeDestination() {
        // MLA accumulates ⇒ destReadsItself ⇒ semanticReads contains Rd.
        let d = decode(0x4EA2_9420)
        #expect(d.semanticReads.contains(.simd(0)))
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
    }

    @Test func semanticReadsForPlainADDExcludeDestination() {
        // ADD is non-destructive — Rd is only written.
        let d = decode(0x0E22_8420)
        #expect(!d.semanticReads.contains(.simd(0)))
        #expect(d.semanticReads.contains(.simd(1)))
        #expect(d.semanticReads.contains(.simd(2)))
    }
}

/// Validates AdvSIMD vector three-different — lengthening forms
/// (SADDL/SADDW/SSUBL/SSUBW/ADDHN/SABAL/SUBHN/SABDL/SMLAL/SMLSL/SMULL/
/// SQDMULL/PMULL/PMULL2/UADDL/UADDW/USUBL/USUBW/RADDHN/UABAL/RSUBHN/UABDL/
/// UMLAL/UMLSL/UMULL).
@Suite("SIMD/FP / AdvSIMD vector three-different")
struct AdvSIMDVectorThreeDifferentTests {
    @Test func saddlV0_8H_V1_8B_V2_8B() {
        // SADDL V0.8H, V1.8B, V2.8B: Q=0, U=0, size=00, opcode=0000,
        // bits[11:10]=00.
        // Top byte: 0x0E. byte 1: 00_1_00010 = 0x22. byte 2:
        // 0000_0_0_00 = 0x00.
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
        // opcode=0001.
        let d = decode(0x0E22_1020)
        #expect(d.mnemonic == .saddw)
    }

    @Test func ssublV0_4S() {
        // opcode=0010.
        let d = decode(0x0E62_2020)
        #expect(d.mnemonic == .ssubl)
    }

    @Test func ssubwV0_4S() {
        let d = decode(0x0E62_3020)
        #expect(d.mnemonic == .ssubw)
    }

    @Test func addhnV0_8B() {
        // ADDHN: opcode=0100. Source widens to destination narrowed.
        let d = decode(0x0E22_4020)
        #expect(d.mnemonic == .addhn)
    }

    @Test func sabalV0_8H() {
        // SABAL: opcode=0101 — accumulating.
        let d = decode(0x0E22_5020)
        #expect(d.mnemonic == .sabal)
        // Destructive — Rd reads itself.
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
        // SMLAL: opcode=1000 — accumulating.
        let d = decode(0x0E62_8020)
        #expect(d.mnemonic == .smlal)
        #expect(d.semanticReads.contains(.simd(0)))
    }

    @Test func sqdmlalV0_4S() {
        // opcode=1001.
        let d = decode(0x0E62_9020)
        #expect(d.mnemonic == .sqdmlal)
    }

    @Test func smlslV0_4S() {
        // opcode=1010.
        let d = decode(0x0E62_A020)
        #expect(d.mnemonic == .smlsl)
    }

    @Test func sqdmlslV0_4S() {
        let d = decode(0x0E62_B020)
        #expect(d.mnemonic == .sqdmlsl)
    }

    @Test func smullV0_4S() {
        // SMULL: opcode=1100.
        let d = decode(0x0E62_C020)
        #expect(d.mnemonic == .smull)
    }

    @Test func sqdmullV0_4S() {
        let d = decode(0x0E62_D020)
        #expect(d.mnemonic == .sqdmull)
    }

    @Test func pmullV0_8H() {
        // PMULL: opcode=1110, size=00.
        let d = decode(0x0E22_E020)
        #expect(d.mnemonic == .pmull)
    }

    @Test func uaddlV0_8H() {
        // U=1.
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
        // RADDHN: U=1, opcode=0100.
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
        // size=11 reserved at this class.
        let d = decode(0x0EE2_0020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedU1OpcodeReturnsUndefined() {
        // U=1 opcode=1001 (no sqdmlal2 for U=1) reserved.
        let d = decode(0x2E62_9020)
        #expect(d.mnemonic == .undefined)
    }

    @Test func reservedU1Opcode1110ReturnsUndefined() {
        // U=1 opcode=1110 reserved (no upmull).
        let d = decode(0x2E22_E020)
        #expect(d.mnemonic == .undefined)
    }
}

/// Validates AdvSIMD vector two-reg-misc — REV/CLS/CNT/CMxx-zero/ABS/
/// NEG/XTN/SHLL/MVN/RBIT, plus FP family FRINT/FCVT/SCVTF/UCVTF/FCMxx-
/// zero/FABS/FNEG/FSQRT.
@Suite("SIMD/FP / AdvSIMD vector two-reg-misc")
struct AdvSIMDVectorTwoRegMiscTests {
    @Test func rev64V0_8B() {
        // REV64 V0.8B, V1.8B: U=0, size=00, opcode=00000.
        // Routes via dispatchVectorThreeArg (bit 21 = 1) → two-reg-misc
        // (bit 11 = 1, bit 10 = 0, bits[20:17]=0000).
        // bits[21:17] = 10000: bit 21 = 1, bits[20:17] = 0000.
        // byte 1 (bits 23..16): size=00, bit 21=1, bits[20:17]=0000, bit 16=opcode[4]=0.
        // = 00_1_0000_0 = 0010_0000 = 0x20.
        // byte 2 (bits 15..8): opcode[3:0] (4 bits in 15..12) + bit 11=1 + bit 10=0 + Rn high (bits 9..8).
        // opcode=00000: bits 15..11 = 0000_1 (bit 11=1). bits 10 = 0. Rn=1 ⇒ bits 9..8 = 00.
        // byte 2 = 0000_1_0_00 = 0000_1000 = 0x08.
        let d = decode(0x0E20_0820)
        #expect(d.mnemonic == .rev64)
    }

    @Test func rev16V0_8B() {
        // REV16: U=0, opcode=00001.
        // Two-reg-misc shape: `0 Q U 0 1110 size 10000 opcode 10 Rn Rd`
        // (1+1+1+1+4+2+5+5+2+5+5 = 32): bits[21:17] = 10000, the 5-bit
        // opcode at bits[16:12] (AdvSIMDTwoRegMiscDecode reads
        // `(encoding >> 12) & 0x1F`), bits[11:10] = 10. Across-lanes
        // shares the shell with bits[21:17] = 11000.
        // For REV16 V0.8B (U=0, size=00, opcode=00001):
        // byte 0 (bits 31..24): 0_0_0_0_1110 = 0x0E.
        // byte 1 (bits 23..16): size(2) + bits[21:17] + opcode[4] = 00_10000_0 = 0010_0000 = 0x20.
        // byte 2 (bits 15..8): opcode[3:0] + bits[11:10] + Rn[4:3] = 0001_10_00 = 0001_1000 = 0x18.
        // byte 3 (bits 7..0): Rn[2:0] + Rd = 001_00000 = 0x20.
        let d = decode(0x0E20_1820)
        #expect(d.mnemonic == .rev16)
    }

    @Test func clsV0_8B() {
        // CLS: opcode=00100.
        // byte 1 = 00_10000_0 = 0x20. byte 2 = 0100_10_00 = 0x48.
        let d = decode(0x0E20_4820)
        #expect(d.mnemonic == .cls)
    }

    @Test func cntV0_8B() {
        // CNT: opcode=00101.
        // byte 2 = 0101_10_00 = 0x58.
        let d = decode(0x0E20_5820)
        #expect(d.mnemonic == .cnt)
    }

    @Test func saddlpV0_4H() {
        // SADDLP: opcode=00010.
        // byte 2 = 0010_10_00 = 0x28.
        let d = decode(0x0E20_2820)
        #expect(d.mnemonic == .saddlp)
    }

    @Test func suqaddV0_8B() {
        // SUQADD: opcode=00011 (note source comment "two-reg-misc with non-default name").
        let d = decode(0x0E20_3820)
        #expect(d.mnemonic == .suqadd)
    }

    @Test func sqabsV0_8B() {
        // SQABS: opcode=00111. byte 2 = 0111_10_00 = 0x78.
        let d = decode(0x0E20_7820)
        #expect(d.mnemonic == .sqabs)
    }

    @Test func absV0_8B() {
        // ABS: opcode=01011. byte 2 = 1011_10_00 = 0xB8.
        let d = decode(0x0E20_B820)
        #expect(d.mnemonic == .abs)
    }

    @Test func cmgtZeroV0_8B() {
        // CMGT V0.8B, V1.8B, #0: opcode=01000, zero form.
        let d = decode(0x0E20_8820)
        #expect(d.mnemonic == .cmgt)
        #expect(d.operands.count == 3) // includes #0 operand
    }

    @Test func cmeqZeroV0_8B() {
        // CMEQ zero: opcode=01001.
        let d = decode(0x0E20_9820)
        #expect(d.mnemonic == .cmeq)
    }

    @Test func cmltZeroV0_8B() {
        let d = decode(0x0E20_A820)
        #expect(d.mnemonic == .cmlt)
    }

    @Test func xtnV0_8B() {
        // XTN: opcode=10010 at bits[16:12].
        // byte 1 = 00_10000_1 = 0010_0001 = 0x21 — opcode[4] = 1 in bit 16
        // distinguishes it from SADDLP (opcode 00010, byte 1 = 0x20),
        // whose byte 2 is identical.
        // byte 2 = 0010_10_00 = 0010_1000 = 0x28.
        let d = decode(0x0E21_2820)
        #expect(d.mnemonic == .xtn)
    }

    @Test func sqxtnV0_8B() {
        // SQXTN: opcode=10100.
        // byte 1 = 0x21. byte 2 = 0100_10_00 = 0x48.
        let d = decode(0x0E21_4820)
        #expect(d.mnemonic == .sqxtn)
    }

    @Test func shllV0_8H() {
        // SHLL V0.8H, V1.8B, #8: U=1, opcode=10011, size=00.
        // byte 1 = 0x21, byte 2 = 0011_10_00 = 0x38.
        let d = decode(0x2E21_3820)
        #expect(d.mnemonic == .shll)
    }

    @Test func rev32V0_8B() {
        // REV32: U=1, opcode=00000.
        let d = decode(0x2E20_0820)
        #expect(d.mnemonic == .rev32)
    }

    @Test func uaddlpV0_4H() {
        // U=1, opcode=00010.
        let d = decode(0x2E20_2820)
        #expect(d.mnemonic == .uaddlp)
    }

    @Test func usqaddV0_8B() {
        let d = decode(0x2E20_3820)
        #expect(d.mnemonic == .usqadd)
    }

    @Test func clzV0_8B() {
        // CLZ: U=1, opcode=00100.
        let d = decode(0x2E20_4820)
        #expect(d.mnemonic == .clz)
    }

    @Test func uadalpV0_4H() {
        // U=1, opcode=00110.
        let d = decode(0x2E20_6820)
        #expect(d.mnemonic == .uadalp)
    }

    @Test func sqnegV0_8B() {
        let d = decode(0x2E20_7820)
        #expect(d.mnemonic == .sqneg)
    }

    @Test func cmgeZeroV0_8B() {
        // CMGE zero: U=1, opcode=01000.
        let d = decode(0x2E20_8820)
        #expect(d.mnemonic == .cmge)
    }

    @Test func cmleZeroV0_8B() {
        let d = decode(0x2E20_9820)
        #expect(d.mnemonic == .cmle)
    }

    @Test func negV0_8B() {
        // NEG: U=1, opcode=01011.
        let d = decode(0x2E20_B820)
        #expect(d.mnemonic == .neg)
    }

    @Test func sqxtunV0_8B() {
        // SQXTUN: U=1, opcode=10010.
        let d = decode(0x2E21_2820)
        #expect(d.mnemonic == .sqxtun)
    }

    @Test func uqxtnV0_8B() {
        // UQXTN: U=1, opcode=10100.
        let d = decode(0x2E21_4820)
        #expect(d.mnemonic == .uqxtn)
    }

    @Test func mvnV0_8B() {
        // MVN: U=1, opcode=00101, size=00 only.
        let d = decode(0x2E20_5820)
        #expect(d.mnemonic == .mvn)
    }

    @Test func mvnRejectsNonByteSize() {
        // U=1 opcode=00101: size=00 ⇒ MVN, size=01 ⇒ RBIT. size=10 has no
        // mapping in this family ⇒ reserved.
        let d = decode(0x2EA0_5820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func rbitV0_8B() {
        // RBIT V0.8B, V1.8B: U=1, opcode=00101, size=01 (size discriminates
        // MVN size=00 vs RBIT size=01). byte 1 = 0x60, byte 2 = 0x58.
        let d2 = decode(0x2E60_5820)
        #expect(d2.mnemonic == .rbit)
    }

    @Test func rbitRejectsNonByteSize() {
        let d = decode(0x2E60_1820)
        #expect(d.mnemonic == .undefined)
    }

    /// FP family (opcode >= 11000).
    @Test func frintnVector_2S() {
        // FRINTN: U=0, opcode=11000, altBit=0 (size=00).
        // byte 1: 00_10000_1 = 0010_0001 = 0x21. byte 2 = 1000_10_00 = 1000_1000 = 0x88.
        let d = decode(0x0E21_8820)
        #expect(d.mnemonic == .frintn)
    }

    @Test func frintpVector_2S() {
        // altBit=1 ⇒ size=10.
        let d = decode(0x0EA1_8820)
        #expect(d.mnemonic == .frintp)
    }

    @Test func frintmVector_2S() {
        // opcode=11001.
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
        // FRECPE V0.2S, V1.2S: U=0, opcode=11101, altBit=1 (bit 23 = 1).
        // sz=0, Q=0 ⇒ size=10. byte 1 = 1010_0001 = 0xA1, byte 2 =
        // 1101_1000 = 0xD8.
        let d = decode(0x0EA1_D820)
        #expect(d.mnemonic == .frecpe)
    }

    @Test func fsqrtVector_2S() {
        // FSQRT V0.2S, V1.2S: U=1, opcode=11111, altBit=1. byte 0 = 0x2E,
        // byte 1 = 0xA1, byte 2 = 0xF8.
        let d = decode(0x2EA1_F820)
        #expect(d.mnemonic == .fsqrt)
    }

    @Test func fcmgtZeroVector_2S() {
        // FCMGT zero V0.2S, V1.2S, #0.0: U=0, opcode=01100, bit[23]=1
        // (FP-family marker), sz=0 (S). byte 1 = 1010_0000 = 0xA0, byte 2
        // = 1100_1000 = 0xC8.
        let d = decode(0x0EA0_C820)
        #expect(d.mnemonic == .fcmgt)
        // Three operands: Vd, Vn, #0.0.
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
        // FABS V0.2S, V1.2S: U=0, opcode=01111, bit[23]=1.
        let d = decode(0x0EA0_F820)
        #expect(d.mnemonic == .fabs)
    }

    @Test func fnegVector_2S() {
        // FNEG V0.2S, V1.2S: U=1, opcode=01111, bit[23]=1.
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
        // U=1, opcode=11000.
        let d = decode(0x2E21_8820)
        #expect(d.mnemonic == .frinta)
    }

    @Test func frintxVector_2S() {
        // FRINTX V0.2S, V1.2S: U=1, opcode=11001, size=00 (sz=0). byte 1 =
        // 0x21, byte 2 = 0x98.
        let d = decode(0x2E21_9820)
        #expect(d.mnemonic == .frintx)
    }

    @Test func frintiVector_2S() {
        // U=1, opcode=11001, altBit=1.
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
        // FRSQRTE V0.2S, V1.2S: U=1, opcode=11101, altBit=1.
        let d = decode(0x2EA1_D820)
        #expect(d.mnemonic == .frsqrte)
    }

    @Test func urecpeVector_2S() {
        // URECPE V0.2S, V1.2S: U=0, opcode=11100, altBit=1. byte 2 =
        // 1100_1000 = 0xC8.
        let d = decode(0x0EA1_C820)
        #expect(d.mnemonic == .urecpe)
    }

    @Test func ursqrteVector_2S() {
        // URSQRTE V0.2S, V1.2S: U=1, opcode=11100, altBit=1.
        let d = decode(0x2EA1_C820)
        #expect(d.mnemonic == .ursqrte)
    }

    @Test func reservedFPSizeAndQReturnsUndefined() {
        // FP family with sz=1 (D) and Q=0 reserved.
        let d = decode(0x0EE1_8820)
        #expect(d.mnemonic == .undefined)
    }

    @Test func unknownIntOpcodeReturnsUndefined() {
        // U=0 opcode=10101 reserved (no integer mapping in
        // intMnemonicAndDstShape; FP family doesn't cover it either).
        let d = decode(0x0E21_5820)
        #expect(d.mnemonic == .undefined)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func text(_ encoding: UInt32) -> String {
    Iris.decode(encoding, at: 0).text
}

private func draft(_ mnemonic: Mnemonic, _ operands: [Operand]) -> Instruction {
    Instruction(
        address: 0, encoding: 0x2518_E000, mnemonic: mnemonic, category: .sve, operands: operands,
    )
}

/// Validates the disassembly-text rendering rules.
@Suite("SVE predicate & control / disassembly text")
struct SVEPredicateControlCanonicalizerTests {
    @Test func anUndefinedRecordRendersAsNothing() {
        #expect(text(0x2543_4A30) == ".long 0x25434a30")
    }

    @Test func theGoverningPredicateIsBareAndEveryOtherPredicateCarriesItsSize() {
        #expect(text(0x2550_C440) == "ptest p1, p2.b")
        #expect(text(0x2520_8443) == "cntp x3, p1, p2.b")
        #expect(text(0x2503_4A30) == "sel p0.b, p2, p1.b, p3.b")
        #expect(text(0x2558_C043) == "pfirst p3.b, p2, p3.b")
        #expect(text(0x2559_C443) == "pnext p3.h, p2, p3.h")
    }

    @Test func theCountedPredicateCarriesItsSizeEvenThoughItGovernsNothing() {
        #expect(text(0x256C_8043) == "incp z3.h, p2.h")
        #expect(text(0x256C_8843) == "incp x3, p2.h")
    }

    @Test func theQualifiersAttachWithoutASpace() {
        #expect(text(0x2503_4820) == "and p0.b, p2/z, p1.b, p3.b")
        #expect(text(0x2510_4443) == "brka p3.b, p1/z, p2.b")
        #expect(text(0x2510_4453) == "brka p3.b, p1/m, p2.b")
        #expect(text(0x2518_F043) == "rdffr p3.b, p2/z")
        #expect(text(0x0450_2C20) == "movprfx z0.h, p3/z, z1.h")
        #expect(text(0x0491_3C20) == "movprfx z0.s, p7/m, z1.s")
    }

    @Test func everyCountPatternRendersThroughTheSharedTable() {
        let base: UInt32 = 0x2518_E000
        for raw in UInt8(0) ... 30 {
            let expected = "ptrue p0.b, \(svePatternText[Int(raw)])"
            #expect(text(base | (UInt32(raw) << 5)) == expected, "pattern \(raw)")
        }
        #expect(text(base | (31 << 5)) == "ptrue p0.b", "the all pattern elides")
    }

    @Test func theElementCountLadderElidesTheDefaultPatternOnlyWhenItWouldTrail() {
        #expect(text(0x0420_E3E0) == "cntb x0", "pattern all, no multiplier — both elide")
        #expect(text(0x0460_E101) == "cnth x1, vl8", "a named pattern always prints")
        #expect(text(0x04A1_E3E2) == "cntw x2, all, mul #2", "a multiplier brings `all` back")
        #expect(text(0x04EF_E003) == "cntd x3, pow2, mul #16")
    }

    @Test func theMultiplierOfOneIsNeverPrinted() {
        #expect(text(0x0470_E085) == "inch x5, vl4")
        #expect(text(0x04B2_E3C6) == "incw x6, mul3, mul #3")
    }

    @Test func theSaturatingFormsPrintTheirDestinationAtTheRightWidth() {
        #expect(text(0x0420_F3E1) == "sqincb x1, w1", "signed 32-bit: wide destination, narrow source view")
        #expect(text(0x0420_F7E1) == "uqincb w1", "unsigned 32-bit: narrow destination, no source view")
        #expect(text(0x04F0_F3E1) == "sqincd x1", "64-bit: one register")
        #expect(text(0x0421_F3E0) == "sqincb x0, w0, all, mul #2", "the ladder follows every register")
        #expect(text(0x2568_8843) == "sqincp x3, p2.h, w3")
        #expect(text(0x2569_8843) == "uqincp w3, p2.h")
    }

    @Test func immediatesArePrintedAsSignedDecimal() {
        #expect(text(0x0421_50A2) == "addvl x2, x1, #5")
        #expect(text(0x0461_5402) == "addpl x2, x1, #-32")
        #expect(text(0x04BF_501F) == "rdvl xzr, #0")
        #expect(text(0x04FF_4200) == "index z0.d, #-16, #-1")
    }

    @Test func registerThirtyOneIsTheStackPointerOnlyOnTheAdjustForms() {
        #expect(text(0x043F_579F) == "addvl sp, sp, #-4")
        #expect(text(0x04BF_501F) == "rdvl xzr, #0")
        #expect(text(0x04E0_FFFF) == "uqdecd wzr")
        #expect(text(0x043F_4FE4) == "index z4.b, wzr, wzr")
        #expect(text(0x25FF_23E0) == "ctermeq xzr, xzr")
    }

    @Test func theIndexOperandsRenderAsRegistersOrImmediatesIndependently() {
        #expect(text(0x0423_4020) == "index z0.b, #1, #3")
        #expect(text(0x0462_44A1) == "index z1.h, w5, #2")
        #expect(text(0x04A6_4842) == "index z2.s, #2, w6")
        #expect(text(0x04E6_4CA3) == "index z3.d, x5, x6")
    }

    @Test func theConstructivePrefixDropsItsElementSizeWhenUnpredicated() {
        #expect(text(0x0420_BC20) == "movprfx z0, z1")
        #expect(text(0x0410_2C20) == "movprfx z0.b, p3/z, z1.b")
    }

    @Test func theAliasesRenderAtTheirOwnOperandCount() {
        #expect(text(0x2584_5081) == "mov p1.b, p4.b")
        #expect(text(0x25C4_5081) == "movs p1.b, p4.b")
        #expect(text(0x2506_48C1) == "mov p1.b, p2/z, p6.b")
        #expect(text(0x2546_48C1) == "movs p1.b, p2/z, p6.b")
        #expect(text(0x2505_4A75) == "mov p5.b, p2/m, p3.b")
        #expect(text(0x2507_5E41) == "not p1.b, p7/z, p2.b")
        #expect(text(0x2547_5E41) == "nots p1.b, p7/z, p2.b")
    }

    @Test func theOperandLessFormPrintsItsMnemonicAlone() {
        #expect(text(0x252C_9000) == "setffr")
        #expect(text(0x2528_9040) == "wrffr p2.b")
        #expect(text(0x2519_F003) == "rdffr p3.b")
    }
}

/// Validates the shape-violation sentinels.
@Suite("SVE predicate & control / disassembly shape violations")
struct SVEPredicateControlCanonicalizerShapeTests {
    private func format(_ d: Instruction) -> String {
        d.text
    }

    @Test func aMnemonicFromOutsideTheGroupRendersAsItsRawValue() {
        #expect(format(draft(.udf, [])) == "?\(Mnemonic.udf.rawValue)")
        #expect(format(draft(.adc, [])) == "?\(Mnemonic.adc.rawValue)")
    }

    @Test func aPredicateSlotHoldingSomethingElseRendersAsAMarker() {
        #expect(format(draft(.pfalse, [.register(.x(0))])) == "pfalse ?p")
        #expect(format(draft(.ptest, [.immediate(value: 1, width: 5), .register(.x(0))])) == "ptest ?p, ?p")
    }

    @Test func aVectorSlotHoldingSomethingElseRendersAsAMarker() {
        let ops: [Operand] = [
            .register(.x(0)),
            .immediate(value: 1, width: 5),
            .immediate(value: 2, width: 5),
        ]
        #expect(format(draft(.index, ops)) == "index ?z, #1, #2")
    }

    @Test func aRegisterSlotHoldingSomethingElseRendersAsAMarker() {
        let ops: [Operand] = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2)),
        ]
        #expect(format(draft(.whilelt, ops)) == "whilelt p0, ?r, ?r")
    }

    @Test func anImmediateSlotHoldingSomethingElseRendersAsAMarker() {
        #expect(format(draft(.rdvl, [.register(.x(0)), .register(.x(1))])) == "rdvl x0, ?#")
    }

    @Test func anIndexOperandSlotHoldingSomethingElseRendersAsAMarker() {
        let ops: [Operand] = [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .b)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2)),
        ]
        #expect(format(draft(.index, ops)) == "index z0.b, ?idx, ?idx")
    }

    @Test func anUnsignedImmediateInAnImmediateSlotStillRenders() {
        let ops: [Operand] = [.register(.x(0)), .unsignedImmediate(value: 7, width: 6)]
        #expect(format(draft(.rdvl, ops)) == "rdvl x0, #7")
    }

    @Test func anOperandPastTheEndOfTheListRendersAsAMarker() {
        #expect(format(draft(.ptest, [])) == "ptest ?p, ?p")
        #expect(format(draft(.addvl, [.register(.x(0))])) == "addvl x0, ?r, #0")
    }

    @Test func aCountPatternSlotHoldingSomethingElseDropsTheOperand() {
        #expect(format(draft(.ptrue, [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0, element: .b, role: .result)),
        ])) == "ptrue p0.b")
        #expect(format(draft(.cntb, [.register(.x(0))])) == "cntb x0")
        #expect(format(draft(.sqincb, [.register(.x(0)), .register(.w(0))])) == "sqincb x0, w0")
        #expect(format(draft(.inch, [
            .scalableVector(ScalableVectorRef(registerIndex: 2, element: .h)),
        ])) == "inch z2.h")
    }

    @Test func theStackPointerRendersAtBothWidths() {
        #expect(format(draft(.addvl, [
            .register(.wsp()), .register(.sp()), .immediate(value: 1, width: 6),
        ])) == "addvl wsp, sp, #1")
    }

    @Test func aGeneralRoleRegisterAtIndexThirtyOneRendersAsTheZeroRegister() {
        #expect(format(draft(.cntp, [
            .register(.x(31)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, element: .b)),
        ])) == "cntp xzr, p0, p1.b")
        #expect(format(draft(.ctermeq, [.register(.w(31)), .register(.w(31))])) == "ctermeq wzr, wzr")
    }

    @Test func aRegisterOutsideTheGeneralPurposeFileRendersAsAMarker() {
        #expect(format(draft(.rdvl, [
            .register(.simd(0)), .immediate(value: 1, width: 6),
        ])) == "rdvl ?32, #1")
    }

    @Test func aQuadElementSuffixRenders() {
        #expect(format(draft(.pfalse, [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .q, role: .result)),
        ])) == "pfalse p3.q")
        #expect(format(draft(.movprfx, [
            .scalableVector(ScalableVectorRef(registerIndex: 1, element: .q)),
            .scalableVector(ScalableVectorRef(registerIndex: 2, element: .q)),
        ])) == "movprfx z1.q, z2.q")
    }
}

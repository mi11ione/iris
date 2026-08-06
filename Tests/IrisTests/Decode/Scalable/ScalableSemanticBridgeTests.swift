// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decoded(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private let bridgeCases: [(word: UInt32, region: String)] = [
    (0x2518_E020, "SVE predicate & control"),
    (0x04C3_03E1, "SVE integer"),
    (0x6508_0840, "SVE floating-point"),
    (0x844F_7FC0, "SVE permute/memory"),
    (0x2521_801F, "SVE predicate-as-counter carve"),
    (0x8080_FC00, "SME core"),
    (0xC150_64C4, "SME2 multi-vector"),
]

/// Validates that the scalable semantic bridge routes every region to the
/// checker that owns it, and maps its issue rather than swallowing it.
@Suite("Scalable semantic bridge — every region routes to its checker")
struct ScalableSemanticBridgeTests {
    @Test func cleanRecordsFromEveryRegionReportNoIssue() {
        for c in bridgeCases {
            #expect(scalableSemanticIssue(for: decoded(c.word)) == nil, "\(c.region)")
        }
    }

    @Test func aPerturbedRecordFromEveryRegionIsReported() {
        for c in bridgeCases {
            let issue = scalableSemanticIssue(for: mutated(decoded(c.word), branchClass: .exception))
            #expect(issue != nil, "\(c.region)")
            #expect(issue?.field.isEmpty == false, "\(c.region)")
            #expect(issue?.actual != issue?.expected, "\(c.region)")
        }
    }

    @Test func aNonScalableRecordIsNotChecked() {
        #expect(scalableSemanticIssue(for: decoded(0xD503_201F)) == nil)
    }

    @Test func anSVERecordOutsideEveryFamilyClaimIsNotChecked() {
        let orphan = Instruction(encoding: 0xD503_201F, mnemonic: .undefined, category: .sve)
        #expect(scalableSemanticIssue(for: orphan) == nil)
    }
}

/// The SVE-FP table's operand-to-register-mask helper is public because the
/// sweep reports on it, and it accepts the whole operand vocabulary.
@Suite("SVE-FP semantics — operand register masks")
struct SVEFloatingPointRegisterMaskTests {
    @Test func aScalableVectorMasksItsOwnRegister() {
        let z3 = Operand.scalableVector(ScalableVectorRef(registerIndex: 3, element: .d))
        #expect(SVEFloatingPointSemanticAttributes.registerMask(z3) == UInt64(1) << 35)
    }

    @Test func aVectorRegisterMasksTheSamePhysicalRegister() {
        let v3 = Operand.vectorRegister(VectorRegisterRef(registerIndex: 3, view: .scalar(size: .d)))
        #expect(SVEFloatingPointSemanticAttributes.registerMask(v3) == UInt64(1) << 35)
    }

    @Test func aVectorGroupMasksEveryMember() {
        let pair = ScalableVectorGroup(firstIndex: 2, count: 2, element: .s, layout: .consecutive)
        let expected = UInt64(1) << 34 | UInt64(1) << 35
        #expect(SVEFloatingPointSemanticAttributes.registerMask(.scalableVectorGroup(pair)) == expected)
    }

    @Test func anOperandWithNoRegistersMasksNothing() {
        #expect(SVEFloatingPointSemanticAttributes.registerMask(.register(.x(0))) == 0)
    }
}

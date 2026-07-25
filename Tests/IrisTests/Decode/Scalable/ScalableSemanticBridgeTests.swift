// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decoded(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

/// One in-scope representative per region the bridge routes to. The bridge is
/// the seam the `iris-parity semantic` sweep drives, so every arm must reach
/// the checker that owns the region — a mis-route would silently validate a
/// record against the wrong expectations.
private let bridgeCases: [(word: UInt32, region: String)] = [
    (0x2518_E020, "SVE predicate & control"), // ptrue p0.b, vl1
    (0x04C3_03E1, "SVE integer"), // subr z1.d, p0/m, z1.d, z31.d
    (0x6508_0840, "SVE floating-point"), // bfmul z0.h, z2.h, z8.h
    (0x844F_7FC0, "SVE permute/memory"), // ldff1b { z0.s }, p7/z, …
    (0x2521_801F, "SVE predicate-as-counter carve"), // firstp xzr, p0, p0.b
    (0x8080_FC00, "SME core"), // fmopa za0.s, …
    (0xC150_64C4, "SME2 multi-vector"), // fmla za.s[w11, 4, vgx2], …
]

@Suite("Scalable semantic bridge — every region routes to its checker")
struct ScalableSemanticBridgeTests {
    /// A record the decoder really produced satisfies its region's checker, so
    /// the bridge reports nothing.
    @Test func cleanRecordsFromEveryRegionReportNoIssue() {
        for c in bridgeCases {
            #expect(scalableSemanticIssue(for: decoded(c.word)) == nil, "\(c.region)")
        }
    }

    /// Perturbing one attribute the checkers all police (`branchClass` — no
    /// scalable record branches) must surface through the bridge as a
    /// `(field, actual, expected)` triple, which is what proves each arm both
    /// routes to a checker and maps its issue rather than swallowing it.
    @Test func aPerturbedRecordFromEveryRegionIsReported() {
        for c in bridgeCases {
            let issue = scalableSemanticIssue(for: mutated(decoded(c.word), branchClass: .exception))
            #expect(issue != nil, "\(c.region)")
            #expect(issue?.field.isEmpty == false, "\(c.region)")
            #expect(issue?.actual != issue?.expected, "\(c.region)")
        }
    }

    /// A non-scalable category is not the bridge's business — it returns `nil`
    /// without consulting any checker.
    @Test func aNonScalableRecordIsNotChecked() {
        #expect(scalableSemanticIssue(for: decoded(0xD503_201F)) == nil) // nop
    }

    /// A `.sve`-tagged record whose word no SVE family predicate claims (here a
    /// word from outside the SVE tier entirely) finds no checker and reports
    /// nothing, rather than defaulting into one that does not own it.
    @Test func anSVERecordOutsideEveryFamilyClaimIsNotChecked() {
        let orphan = Instruction(encoding: 0xD503_201F, mnemonic: .undefined, category: .sve)
        #expect(scalableSemanticIssue(for: orphan) == nil)
    }
}

/// The SVE-FP expected-attribute table's operand→register-mask helper is
/// public because the sweep reports on it, and it accepts the whole operand
/// vocabulary: a Z vector, a V register (the same physical register), a vector
/// group (every member), and anything else (no registers).
@Suite("SVE-FP semantics — operand register masks")
struct SVEFloatingPointRegisterMaskTests {
    @Test func aScalableVectorMasksItsOwnRegister() {
        let z3 = Operand.scalableVector(ScalableVectorRef(registerIndex: 3, element: .d))
        #expect(SVEFloatingPointSemanticAttributes.registerMask(z3) == UInt64(1) << 35)
    }

    /// `Vn` and `Zn` are the same physical register, so both mask at 32+n.
    @Test func aVectorRegisterMasksTheSamePhysicalRegister() {
        let v3 = Operand.vectorRegister(VectorRegisterRef(registerIndex: 3, view: .scalar(size: .d)))
        #expect(SVEFloatingPointSemanticAttributes.registerMask(v3) == UInt64(1) << 35)
    }

    @Test func aVectorGroupMasksEveryMember() {
        let pair = ScalableVectorGroup(firstIndex: 2, count: 2, element: .s, layout: .consecutive)
        let expected = UInt64(1) << 34 | UInt64(1) << 35 // z2, z3
        #expect(SVEFloatingPointSemanticAttributes.registerMask(.scalableVectorGroup(pair)) == expected)
    }

    @Test func anOperandWithNoRegistersMasksNothing() {
        #expect(SVEFloatingPointSemanticAttributes.registerMask(.register(.x(0))) == 0)
    }
}

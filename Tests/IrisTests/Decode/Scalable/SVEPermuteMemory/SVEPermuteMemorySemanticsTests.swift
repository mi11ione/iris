// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates that the independently-derived semantic model agrees with every
/// decoded 2s.5 record.
@Suite("SVE permute/memory/crypto semantics / consistent records pass")
struct SVEPermuteMemorySemanticsPassTests {
    private static let representatives: [(UInt32, String)] = [
        (0xA400_A000, "ld1b — normal load"),
        (0xE400_E000, "st1b — store"),
        (0x85C0_0000, "prfb — prefetch"),
        (0x0520_6000, "zip1 — register-only permute"),
        (0x4522_E020, "aese — register-only crypto"),
        (0xA400_6000, "ldff1b — first-fault load"),
        (0xA410_A000, "ldnf1b — non-fault load"),
        (0xA400_E000, "ldnt1b — non-temporal load"),
        (0xE410_E000, "stnt1b — non-temporal store"),
        (0x8580_4000, "ldr — register fill"),
    ]

    @Test func everyDecodedFamilyPassesTheChecker() {
        for (encoding, label) in Self.representatives {
            let draft = decode(encoding)
            #expect(
                SVEPermuteMemorySemanticChecker.verify(draft: draft) == nil,
                "\(label) (0x\(String(encoding, radix: 16))) should pass",
            )
        }
    }

    @Test func anUndefinedRecordIsVacuouslyValid() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .undefined,
            branchClass: .exception, memoryAccess: .load, category: .undefined,
        )
        #expect(SVEPermuteMemorySemanticChecker.verify(draft: draft) == nil)
    }
}

/// Validates that the checker actually catches a decode that renders plausibly
/// but mis-tags its semantics.
@Suite("SVE permute/memory/crypto semantics / mismatches are reported")
struct SVEPermuteMemorySemanticsMismatchTests {
    private func loadDraft(
        mnemonic: Mnemonic = .ld1b,
        branchClass: BranchClass = .none,
        memoryAccess: MemoryAccess = .load,
        memoryOrdering: MemoryOrdering = [],
        flagEffect: FlagEffect = .none,
        category: Category = .sve,
        scalableReads: ScalableRegisterSet = .empty,
        scalableWrites: ScalableRegisterSet = .empty,
        scalableEffect: ScalableEffect = .readsStreamingMode,
    ) -> Instruction {
        Instruction(
            address: 0, encoding: 0, mnemonic: mnemonic,
            branchClass: branchClass, memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering, flagEffect: flagEffect, category: category,
            scalableReads: scalableReads, scalableWrites: scalableWrites, scalableEffect: scalableEffect,
        )
    }

    private func field(_ draft: Instruction) -> String? {
        SVEPermuteMemorySemanticChecker.verify(draft: draft)?.field
    }

    @Test func aBaselineLoadDraftPasses() {
        #expect(SVEPermuteMemorySemanticChecker.verify(draft: loadDraft()) == nil)
    }

    @Test func aNonScalableCategoryIsReported() {
        #expect(field(loadDraft(category: .simdAndFP)) == "category")
    }

    @Test func aBranchClassIsReported() {
        #expect(field(loadDraft(branchClass: .exception)) == "branchClass")
    }

    @Test func aFlagEffectIsReported() {
        #expect(field(loadDraft(flagEffect: .writesN)) == "flagEffect")
    }

    @Test func aMemoryOrderingIsReported() {
        #expect(field(loadDraft(memoryOrdering: .acquire)) == "memoryOrdering")
    }

    @Test func aMissingStreamingBlanketIsReported() {
        #expect(field(loadDraft(scalableEffect: .none)) == "readsStreamingMode")
    }

    @Test func aWrongMemoryAccessKindIsReported() {
        #expect(field(loadDraft(memoryAccess: .none)) == "memoryAccess")
        #expect(field(loadDraft(memoryAccess: .store)) == "memoryAccess")
    }

    @Test func aSpuriousFirstFaultFlagIsReported() {
        let draft = loadDraft(scalableEffect: [.readsStreamingMode, .firstFaulting])
        #expect(field(draft) == "firstFaulting")
    }

    @Test func aSpuriousNonFaultFlagIsReported() {
        let draft = loadDraft(scalableEffect: [.readsStreamingMode, .nonFaulting])
        #expect(field(draft) == "nonFaulting")
    }

    @Test func aSpuriousNonTemporalFlagIsReported() {
        let draft = loadDraft(scalableEffect: [.readsStreamingMode, .nonTemporal])
        #expect(field(draft) == "nonTemporal")
    }

    @Test func aMissingFirstFaultFlagOnAnLdff1IsReported() {
        let draft = loadDraft(mnemonic: .ldff1b)
        #expect(field(draft) == "firstFaulting")
    }

    @Test func aSpuriousFFRReadIsReported() {
        let draft = loadDraft(scalableReads: ScalableRegisterSet.empty.insertingFFR())
        #expect(field(draft) == "scalableReads.FFR")
    }

    @Test func aSpuriousFFRWriteIsReported() {
        let draft = loadDraft(scalableWrites: ScalableRegisterSet.empty.insertingFFR())
        #expect(field(draft) == "scalableWrites.FFR")
    }

    @Test func aStreamingModeWriteIsReported() {
        let draft = loadDraft(scalableEffect: [.readsStreamingMode, .writesStreamingMode])
        #expect(field(draft) == "writesStreamingMode")
    }

    @Test func aZAEnableWriteIsReported() {
        let draft = loadDraft(scalableEffect: [.readsStreamingMode, .writesZAEnable])
        #expect(field(draft) == "writesZAEnable")
    }

    @Test func aMissingFFROnANonFaultLoadIsReported() {
        let draft = loadDraft(mnemonic: .ldnf1b, scalableEffect: [.readsStreamingMode, .nonFaulting])
        #expect(field(draft) == "scalableReads.FFR")
    }
}

/// Validates the `SVEPermMemSemanticIssue` value.
@Suite("SVE permute/memory/crypto semantics / issue value")
struct SVEPermMemSemanticIssueTests {
    @Test func theIssueCarriesItsThreeFields() {
        let issue = SVEPermMemSemanticIssue(field: "memoryAccess", actual: "0", expected: "1")
        #expect(issue.field == "memoryAccess")
        #expect(issue.actual == "0")
        #expect(issue.expected == "1")
    }

    @Test func equalIssuesHashEqual() {
        let a = SVEPermMemSemanticIssue(field: "firstFaulting", actual: "set", expected: "unset")
        let b = SVEPermMemSemanticIssue(field: "firstFaulting", actual: "set", expected: "unset")
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func differingIssuesAreDistinct() {
        let a = SVEPermMemSemanticIssue(field: "firstFaulting", actual: "set", expected: "unset")
        let b = SVEPermMemSemanticIssue(field: "nonFaulting", actual: "set", expected: "unset")
        #expect(a != b)
    }
}

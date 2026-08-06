// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decodeSME(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func decodePred(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func perturbedSME(_ e: UInt32, _ body: (inout InstructionImage) -> Void) -> SME2SemanticChecker.Issue? {
    SME2SemanticChecker.verify(draft: perturbing(decodeSME(e), body))
}

private func perturbedPred(_ e: UInt32, _ body: (inout InstructionImage) -> Void) -> SME2SemanticChecker.Issue? {
    SME2SemanticChecker.verify(draft: perturbing(decodePred(e), body))
}

private let smeRepresentatives: [(UInt32, String)] = [
    (0xC1A1_1C00, "fadd — ZA-accumulate"),
    (0x80C0_0008, "fmop4a — MOP4"),
    (0x8140_0008, "ftmopa — TMOP"),
    (0xA080_0008, "smopa — residue"),
    (0xA000_0000, "ld1b — multi-vector load"),
    (0xA000_0001, "ldnt1b — non-temporal load"),
    (0xA020_0000, "st1b — multi-vector store"),
    (0xC120_A300, "add — destructive"),
    (0xC120_8000, "sel"),
    (0xC120_C400, "sclamp"),
    (0xC131_E000, "fcvtzs — convert"),
    (0xC004_0800, "mov — mova array"),
    (0xC002_0200, "movaz — single-slice"),
    (0xC00C_0000, "zero — array"),
    (0xC048_0001, "zero — zt0"),
    (0xC04C_03E0, "movt — Xt from zt0"),
    (0xC04E_03E0, "movt — zt0 from Xt"),
    (0xC08A_0000, "luti6"),
    (0xE11F_8000, "ldr zt0"),
    (0xE13F_8000, "str zt0"),
]

/// Validates that the independently-derived semantic model agrees with every
/// record the decoder produces.
@Suite("SME2 semantics / consistent records pass")
struct SME2SemanticsPassTests {
    @Test func everyFamilyRepresentativePassesTheChecker() {
        for (encoding, label) in smeRepresentatives {
            #expect(SME2SemanticChecker.verify(draft: decodeSME(encoding)) == nil, "\(label)")
        }
    }

    @Test func everyPredicateCarveRepresentativePassesTheChecker() {
        for encoding: UInt32 in [
            0x2520_4010, 0x2520_5010, 0x2520_7010, 0x2520_7410,
            0x2520_7810, 0x2520_8200, 0x2521_8000, 0x2522_8000, 0x2524_4000,
        ] {
            #expect(SME2SemanticChecker.verify(draft: decodePred(encoding)) == nil, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func anUndefinedSMEHoleIsVacuouslyValid() {
        #expect(SME2SemanticChecker.verify(draft: decodeSME(0xC100_2000)) == nil)
        let manual = Instruction(address: 0, encoding: 0xC100_2000, mnemonic: .undefined, category: .sme)
        #expect(SME2SemanticChecker.verify(draft: manual) == nil)
    }

    @Test func anUndefinedCarveHoleKeepsTheSVECategory() {
        #expect(SME2SemanticChecker.verify(draft: decodePred(0x2520_0000)) == nil)
    }

    @Test func theStreamingSafeTrioIsNotStreamingGated() {
        for encoding: UInt32 in [0xE11F_8000, 0xE13F_8000, 0xC048_0001] {
            let d = decodeSME(encoding)
            #expect(!d.scalableEffect.contains(.readsStreamingMode), "0x\(String(encoding, radix: 16))")
            #expect(SME2SemanticChecker.verify(draft: d) == nil, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theMovtInsertIsPartialWhileTheMovtExtractIsNot() {
        #expect(decodeSME(0xC04E_03E0).scalableEffect.contains(.partialWrite))
        #expect(!decodeSME(0xC04C_03E0).scalableEffect.contains(.partialWrite))
        #expect(SME2SemanticChecker.verify(draft: decodeSME(0xC04E_03E0)) == nil)
        #expect(SME2SemanticChecker.verify(draft: decodeSME(0xC04C_03E0)) == nil)
    }
}

/// Validates that the checker reports a record rendering plausibly but
/// mis-tagging its semantics; each case perturbs one attribute so the
/// reported.
@Suite("SME2 semantics / mismatches are reported")
struct SME2SemanticsMismatchTests {
    @Test func aForeignCategoryIsReported() {
        #expect(perturbedSME(0xC1A1_1C00) { $0.category = .simdAndFP }?.field == "category")
        #expect(perturbedPred(0x2520_4010) { $0.category = .sme }?.field == "category")
    }

    @Test func aBranchClassIsReported() {
        #expect(perturbedSME(0xC1A1_1C00) { $0.branchClass = .exception }?.field == "branchClass")
    }

    @Test func aMemoryOrderingIsReported() {
        #expect(perturbedSME(0xA000_0000) { $0.memoryOrdering = .acquire }?.field == "memoryOrdering")
    }

    @Test func aFlagEffectIsReportedBothWays() {
        #expect(perturbedSME(0xC1A1_1C00) { $0.flagEffect = .nzcv }?.field == "flagEffect")
        #expect(perturbedPred(0x2520_4010) { $0.flagEffect = .none }?.field == "flagEffect")
    }

    @Test func aWrongMemoryKindIsReported() {
        #expect(perturbedSME(0xA000_0000) { $0.memoryAccess = .none }?.field == "memoryAccess")
        #expect(perturbedSME(0xC1A1_1C00) { $0.memoryAccess = .load }?.field == "memoryAccess")
    }

    @Test func aMismatchedZATouchIsReported() {
        #expect(perturbedSME(0xC1A1_1C00) {
            $0.scalableReads = .empty
            $0.scalableWrites = .empty
        }?.field == "za")
        #expect(perturbedSME(0xC120_A300) {
            $0.scalableWrites = ScalableRegisterSet.empty.inserting(.whole)
        }?.field == "za")
    }

    @Test func aMismatchedZT0TouchIsReported() {
        #expect(perturbedSME(0xC08A_0000) { $0.scalableReads = .empty }?.field == "zt0")
    }

    @Test func aMissingStreamingFlagIsReported() {
        let issue = perturbedSME(0xC1A1_1C00) { $0.scalableEffect = [.partialWrite] }
        #expect(issue?.field == "readsStreamingMode")
        #expect(issue?.actual == "false")
        #expect(issue?.expected == "true")
    }

    @Test func aSpuriousStreamingFlagOnANonStreamingFormIsReported() {
        let issue = perturbedSME(0xE11F_8000) { $0.scalableEffect = [.readsStreamingMode] }
        #expect(issue?.field == "readsStreamingMode")
        #expect(issue?.actual == "true")
        #expect(issue?.expected == "false")
    }

    @Test func aMissingPartialWriteIsReported() {
        #expect(perturbedSME(0xC1A1_1C00) { $0.scalableEffect = [.readsStreamingMode] }?.field == "partialWrite")
    }

    @Test func aSpuriousPartialWriteIsReported() {
        #expect(perturbedSME(0xC120_A300) {
            $0.scalableEffect = [.readsStreamingMode, .partialWrite]
        }?.field == "partialWrite")
    }

    @Test func aMismatchedNonTemporalFlagIsReported() {
        #expect(perturbedSME(0xA000_0001) { $0.scalableEffect = [.readsStreamingMode] }?.field == "nonTemporal")
        #expect(perturbedSME(0xA000_0000) {
            $0.scalableEffect = [.readsStreamingMode, .nonTemporal]
        }?.field == "nonTemporal")
    }

    @Test func aModeTransitionEffectIsReported() {
        #expect(perturbedSME(0xC1A1_1C00) { $0.scalableEffect.insert(.writesStreamingMode) }?.field == "writesMode")
        #expect(perturbedSME(0xC1A1_1C00) { $0.scalableEffect.insert(.writesZAEnable) }?.field == "writesMode")
    }
}

/// Validates the `SME2SemanticChecker.Issue` value the checker hands back.
@Suite("SME2 semantics / issue value")
struct SME2SemanticIssueTests {
    @Test func theReportedIssueCarriesItsThreeFields() {
        let issue = perturbedSME(0xC1A1_1C00) { $0.branchClass = .exception }
        #expect(issue?.field == "branchClass")
        #expect(issue?.actual == "\(BranchClass.exception)")
        #expect(issue?.expected == "none")
    }
}

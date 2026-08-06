// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decoded(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private let faddDraft = decoded(0x6540_8440)
private let fcmgeDraft = decoded(0x6543_4445)

/// Validates the independent semantic-attribute re-derivation.
@Suite("SVE floating-point / semantic checker mismatch detection")
struct SVEFloatingPointSemanticCheckerTests {
    @Test func aRealRecordPassesEveryCheck() {
        #expect(SVEFloatingPointSemanticChecker.verify(draft: faddDraft) == nil)
        #expect(SVEFloatingPointSemanticChecker.verify(draft: fcmgeDraft) == nil)
    }

    @Test func anUndefinedRecordIsAcceptedUnconditionally() {
        let d = perturbing(faddDraft) {
            $0.mnemonic = .undefined
            $0.flagEffect = .nzcv
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d) == nil)
    }

    @Test func aWrongCategoryIsCaught() {
        let d = perturbing(faddDraft) {
            $0.category = .simdAndFP
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "category")
    }

    @Test func aBranchOrMemoryClassIsCaught() {
        let branch = perturbing(faddDraft) {
            $0.branchClass = .direct
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: branch)?.field == "branchClass")

        let mem = perturbing(faddDraft) {
            $0.memoryAccess = .load
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: mem)?.field == "memoryAccess")

        let order = perturbing(faddDraft) {
            $0.memoryOrdering = .acquire
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: order)?.field == "memoryOrdering")
    }

    @Test func anyFlagEffectIsCaught() {
        let d = perturbing(fcmgeDraft) {
            $0.flagEffect = .nzcv
        }
        let issue = SVEFloatingPointSemanticChecker.verify(draft: d)
        #expect(issue?.field == "flagEffect")
        #expect(issue?.expected == "\(FlagEffect.none.rawValue)")
    }

    @Test func aWrongScalableEffectIsCaught() {
        let d = perturbing(faddDraft) {
            $0.scalableEffect = .readsStreamingMode
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "scalableEffect")
    }

    @Test func aSpuriousPredicateWriteIsCaught() {
        let d = perturbing(faddDraft) {
            $0.scalableWrites = ScalableRegisterSet.empty.insertingPredicate(3)
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "predicateWrites")
    }

    @Test func aWrongGoverningPredicateReadIsCaught() {
        let d = perturbing(faddDraft) {
            $0.scalableReads = .empty
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "predicateReads")
    }

    @Test func aWrongRegisterWriteOrReadIsCaught() {
        let write = perturbing(faddDraft) {
            $0.semanticWrites = .empty
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: write)?.field == "registerWrites")

        let read = perturbing(faddDraft) {
            $0.semanticReads = .empty
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: read)?.field == "registerReads")
    }
}

/// Validates the pure per-mnemonic / per-operand attribute helpers that the
/// checker composes.
@Suite("SVE floating-point / semantic attribute helpers")
struct SVEFloatingPointSemanticAttributeTests {
    @Test func onlyTopHalfConvertsPreserveTheDestination() {
        for m: Mnemonic in [.fcvtnt, .fcvtxnt, .bfcvtnt] {
            #expect(SVEFloatingPointSemanticAttributes.preservesDestination(m), "\(m.rawValue)")
        }
        for m: Mnemonic in [.fcvtlt, .fadd, .fmla, .fcvt, .fmov] {
            #expect(!SVEFloatingPointSemanticAttributes.preservesDestination(m), "\(m.rawValue)")
        }
    }

    @Test func accumulatorsAndClampsAndTopConvertsReadTheDestination() {
        let reads: [Mnemonic] = [
            .fmla, .fmls, .bfmla, .bfmls, .fcmla, .fdot, .bfdot, .fmmla, .bfmmla,
            .fmlalb, .fmlalt, .fmlslb, .fmlslt, .bfmlalb, .bfmlalt, .bfmlslb, .bfmlslt,
            .fmlallbb, .fmlallbt, .fmlalltb, .fmlalltt, .fclamp, .bfclamp,
            .fcvtnt, .fcvtxnt, .bfcvtnt,
        ]
        for m in reads {
            #expect(SVEFloatingPointSemanticAttributes.readsDestination(m), "\(m.rawValue)")
        }
        for m: Mnemonic in [.fadd, .ftmad, .fadda, .faddv, .fexpa, .fmov] {
            #expect(!SVEFloatingPointSemanticAttributes.readsDestination(m), "\(m.rawValue)")
        }
    }

    @Test func hasMergingGoverningReadsTheOperandList() {
        let merging: Instruction.Operands = [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .h)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .merging, role: .governing)),
        ]
        #expect(SVEFloatingPointSemanticAttributes.hasMergingGoverning(merging))

        let zeroing: Instruction.Operands = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
        ]
        #expect(!SVEFloatingPointSemanticAttributes.hasMergingGoverning(zeroing))
    }

    @Test func expectedScalableEffectFollowsMergingAndPreservation() {
        #expect(SVEFloatingPointSemanticAttributes.expectedScalableEffect(for: faddDraft)
            == [.readsStreamingMode, .partialWrite])
        let fmmla = decoded(0x6422_E020)
        #expect(SVEFloatingPointSemanticAttributes.expectedScalableEffect(for: fmmla) == .readsStreamingMode)
    }

    @Test func theRegisterHelpersReturnZeroForAnOperandlessRecord() {
        let empty = Instruction(address: 0, encoding: 0, mnemonic: .fadd, category: .sve)
        #expect(SVEFloatingPointSemanticAttributes.expectedRegisterWrites(for: empty) == 0)
        #expect(SVEFloatingPointSemanticAttributes.expectedRegisterReads(for: empty) == 0)
    }
}

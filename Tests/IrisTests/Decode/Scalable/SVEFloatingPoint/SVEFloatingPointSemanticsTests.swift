// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// A real decoded record to use as a passing baseline, so each mismatch test
/// mutates exactly one field.
private func decoded(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private let faddDraft = decoded(0x6540_8440) // fadd z0.h, p1/m, z0.h, z2.h
private let fcmgeDraft = decoded(0x6543_4445) // fcmge p5.h, p1/z, z2.h, z3.h

/// Validates the independent semantic-attribute re-derivation for 2s.4. The
/// text validator proves mnemonic + operands, but disassembly does not encode
/// flagEffect, the scalable effects, or the read/write sets — so the checker
/// derives those from the (text-validated) operand list plus the mnemonic and
/// compares. The two rules carrying the weight are `flagEffect == .none` on
/// every form including the compares, and `partialWrite` set exactly on the
/// merging forms plus the statically-preserving top-half converts.
@Suite("SVE floating-point / semantic checker mismatch detection")
struct SVEFloatingPointSemanticCheckerTests {
    @Test func aRealRecordPassesEveryCheck() {
        #expect(SVEFloatingPointSemanticChecker.verify(draft: faddDraft) == nil)
        #expect(SVEFloatingPointSemanticChecker.verify(draft: fcmgeDraft) == nil)
    }

    @Test func anUndefinedRecordIsAcceptedUnconditionally() {
        let d = perturbing(faddDraft) {
            $0.mnemonic = .undefined
            // Even with otherwise-inconsistent fields, an UNDEFINED short-circuits.
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
        // The headline invariant: not one form may touch NZCV.
        let d = perturbing(fcmgeDraft) {
            $0.flagEffect = .nzcv
        }
        let issue = SVEFloatingPointSemanticChecker.verify(draft: d)
        #expect(issue?.field == "flagEffect")
        #expect(issue?.expected == "\(FlagEffect.none.rawValue)")
    }

    @Test func aWrongScalableEffectIsCaught() {
        // fadd is merging, so partialWrite is expected; dropping it diverges.
        let d = perturbing(faddDraft) {
            $0.scalableEffect = .readsStreamingMode
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "scalableEffect")
    }

    @Test func aSpuriousPredicateWriteIsCaught() {
        // fadd writes no predicate; inventing one must be caught.
        let d = perturbing(faddDraft) {
            $0.scalableWrites = ScalableRegisterSet.empty.insertingPredicate(3)
        }
        #expect(SVEFloatingPointSemanticChecker.verify(draft: d)?.field == "predicateWrites")
    }

    @Test func aWrongGoverningPredicateReadIsCaught() {
        let d = perturbing(faddDraft) {
            $0.scalableReads = .empty // the governing Pg read is missing
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
/// checker composes. They classify partial-write and destination-read
/// behaviour from the mnemonic identity and operand shape alone.
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
        // The two-address destructive forms are picked up by the operand walk,
        // not this helper, so it must report false for them.
        for m: Mnemonic in [.fadd, .ftmad, .fadda, .faddv, .fexpa, .fmov] {
            #expect(!SVEFloatingPointSemanticAttributes.readsDestination(m), "\(m.rawValue)")
        }
    }

    @Test func hasMergingGoverningReadsTheOperandList() {
        let merging: [Operand] = [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .h)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .merging, role: .governing)),
        ]
        #expect(SVEFloatingPointSemanticAttributes.hasMergingGoverning(merging))

        let zeroing: [Operand] = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
        ]
        #expect(!SVEFloatingPointSemanticAttributes.hasMergingGoverning(zeroing))
    }

    @Test func expectedScalableEffectFollowsMergingAndPreservation() {
        // A merging record and a top-convert both carry partialWrite; a plain
        // unpredicated accumulator carries only the streaming flag.
        #expect(SVEFloatingPointSemanticAttributes.expectedScalableEffect(for: faddDraft)
            == [.readsStreamingMode, .partialWrite])
        let fmmla = decoded(0x6422_E020)
        #expect(SVEFloatingPointSemanticAttributes.expectedScalableEffect(for: fmmla) == .readsStreamingMode)
    }

    @Test func theRegisterHelpersReturnZeroForAnOperandlessRecord() {
        // An operand-less record has no destination and no sources — the walk
        // over an empty operand list must fall to zero rather than trap.
        let empty = Instruction(address: 0, encoding: 0, mnemonic: .fadd, category: .sve)
        #expect(SVEFloatingPointSemanticAttributes.expectedRegisterWrites(for: empty) == 0)
        #expect(SVEFloatingPointSemanticAttributes.expectedRegisterReads(for: empty) == 0)
    }
}

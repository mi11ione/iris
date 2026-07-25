// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func verify(_ draft: Instruction) -> SVEIntSemanticIssue? {
    SVEIntegerSemanticChecker.verify(draft: draft)
}

/// Validates the semantic-attribute checker. Disassembly text carries the
/// mnemonic and operands and nothing else — it says nothing about NZCV,
/// partial writes, streaming-mode dependence, or the read/write masks, which
/// are exactly what a dataflow consumer runs on. The checker derives each
/// attribute independently from the text-validated operand list, so its own
/// detection has to be exercised field by field: a checker that silently
/// returned nil would leave the whole semantic model unvalidated.
@Suite("SVE integer / semantic-attribute checker")
struct SVEIntegerSemanticCheckerTests {
    @Test func aWellFormedRecordFromEveryGroupPasses() {
        let representatives: [UInt32] = [
            0x0400_0000, // add predicated
            0x0494_0443, // sdiv
            0x0400_8100, // asr immediate
            0x0418_8020, // asr wide
            0x0456_A820, // abs /m
            0x0446_A820, // abs /z
            0x0482_4020, // mla
            0x0481_E040, // msb
            0x0400_2443, // saddv
            0x0405_2443, // addqv
            0x0422_0020, // add unpredicated
            0x0461_3020, // mov from orr
            0x0422_A820, // adr
            0x0421_3840, // eor3
            0x042F_3420, // xar
            0x2402_0020, // cmphs vector
            0x2402_C030, // cmphi wide
            0x243F_C020, // cmphs immediate
            0x2510_8030, // cmpne signed immediate
            0x2560_E000, // add immediate with the unfolded shift
            0x2530_D000, // mul immediate
            0x2538_D000, // mov immediate
            0x0520_3BE0, // mov from wsp
            0x05E8_A3E0, // mov merging from sp
            0x0570_2000, // mov indexed quadword
            0x0510_4000, // mov immediate merging
            0x0502_0000, // orr bitmask
            0x05C0_8020, // mov from dupm
            0x05C0_0620, // dupm
            0x4418_8020, // sqadd predicated
            0x4411_A020, // addp
            0x4482_4020, // smlalb
            0x4482_7020, // sqrdmlah
            0x4482_1C20, // cdot rotated
            0x4402_C020, // sclamp
            0x4408_A020, // sqabs /m
            0x4444_A020, // sadalp
            0x44C1_D840, // madpt
            0x44A2_0020, // sdot indexed
            0x447A_0820, // mla indexed
            0x4502_6820, // pmullb quadword
            0x4502_9020, // eorbt
            0x4502_D020, // adclb
            0x4522_8030, // nmatch
            0x45A2_C020, // histcnt
            0x4522_A020, // histseg
            0x4508_E020, // ssra
            0x4508_F420, // sli
            0x4540_A020, // sshllb
            0x4500_D820, // cadd
            0x4562_6420, // addhnt
            0x4528_4020, // sqxtnb
            0x4528_3C20, // uqrshrnt
            0x4531_4040, // sqcvtn
            0x45B0_0040, // sqshrn multi-vector
        ]
        for encoding in representatives {
            #expect(verify(decode(encoding)) == nil, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func anUndefinedRecordHasNoAttributesToCheck() {
        #expect(verify(decode(0x2530_8000)) == nil)
    }

    @Test func aRecordFromTheWrongCategoryIsRejected() {
        let d = perturbing(decode(0x0400_0000)) {
            $0.category = .simdAndFP
        }
        #expect(verify(d)?.field == "category")
    }

    @Test func aRecordClaimingToBranchIsRejected() {
        let d = perturbing(decode(0x0400_0000)) {
            $0.branchClass = .indirect
        }
        #expect(verify(d)?.field == "branchClass")
    }

    @Test func aRecordClaimingToTouchMemoryIsRejected() {
        // ADR computes an address but never loads
        let d = perturbing(decode(0x0422_A020)) {
            $0.memoryAccess = .load
        }
        #expect(verify(d)?.field == "memoryAccess")
        let ordered = perturbing(decode(0x0400_0000)) {
            $0.memoryOrdering = .acquire
        }
        #expect(verify(ordered)?.field == "memoryOrdering")
    }

    @Test func aFlagEffectOnANonCompareIsRejectedAndAMissingOneOnACompare() {
        let arith = perturbing(decode(0x0400_0000)) {
            $0.flagEffect = .nzcv
        }
        let arithIssue = verify(arith)
        #expect(arithIssue?.field == "flagEffect")
        #expect(arithIssue?.actual != arithIssue?.expected)
        let compare = perturbing(decode(0x2402_0020)) {
            $0.flagEffect = .none
        }
        #expect(verify(compare)?.field == "flagEffect")
    }

    @Test func aWrongPartialWriteIsRejectedInBothDirections() {
        // add …/m is partial
        let merged = perturbing(decode(0x0400_0000)) {
            $0.scalableEffect = .readsStreamingMode
        }
        #expect(verify(merged)?.field == "scalableEffect")
        // add z,z,z is a full write
        let fresh = perturbing(decode(0x0422_0020)) {
            $0.scalableEffect = [.readsStreamingMode, .partialWrite]
        }
        #expect(verify(fresh)?.field == "scalableEffect")
        let streaming = perturbing(decode(0x0422_0020)) {
            $0.scalableEffect = []
        }
        #expect(verify(streaming)?.field == "scalableEffect")
    }

    @Test func strayPredicateOrHighScalableBitsAreRejected() {
        let writes = perturbing(decode(0x2402_0020)) {
            $0.scalableWrites = $0.scalableWrites.insertingPredicate(5)
        }
        #expect(verify(writes)?.field == "predicateWrites")
        let reads = perturbing(decode(0x0400_0000)) {
            $0.scalableReads = $0.scalableReads.insertingPredicate(9)
        }
        #expect(verify(reads)?.field == "predicateReads")
        // The comparison spans the WHOLE scalable set, so a stray bit above
        // the predicate field (an FFR/ZA-style claim) must also be caught.
        let high = perturbing(decode(0x0400_0000)) {
            $0.scalableWrites = ScalableRegisterSet(bits: 1 << 40)
        }
        #expect(verify(high)?.field == "predicateWrites")
    }

    @Test func wrongRegisterMasksAreRejected() {
        let writes = perturbing(decode(0x0422_0020)) {
            $0.semanticWrites = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 9))
        }
        #expect(verify(writes)?.field == "registerWrites")
        let reads = perturbing(decode(0x0422_0020)) {
            $0.semanticReads = .empty
        }
        #expect(verify(reads)?.field == "registerReads")
        let extra = perturbing(decode(0x0422_0020)) {
            $0.semanticReads = $0.semanticReads.inserting(.x(3))
        }
        #expect(verify(extra)?.field == "registerReads")
    }

    @Test func theIssueCarriesItsFieldAndBothValues() {
        let issue = SVEIntSemanticIssue(field: "flagEffect", actual: "1", expected: "0")
        #expect(issue.field == "flagEffect")
        #expect(issue.actual == "1")
        #expect(issue.expected == "0")
        #expect(issue == SVEIntSemanticIssue(field: "flagEffect", actual: "1", expected: "0"))
    }
}

/// Validates the per-mnemonic and per-operand attribute lookups directly —
/// the pure functions the checker composes. The flag set must be exactly the
/// compares plus MATCH/NMATCH; the preserving set exactly the nineteen
/// statically-preserving mnemonics; the destination-read set the accumulators
/// and clamps on top of those; and the register-mask walk must weigh every
/// operand kind the decoders emit, dropping the zero register and keeping SP.
@Suite("SVE integer / semantic-attribute lookups")
struct SVEIntegerSemanticAttributesTests {
    @Test func theFlagWritersAreExactlyTheComparesAndMatches() {
        let writers: [Mnemonic] = [
            .cmpeq, .cmpge, .cmpgt, .cmphi, .cmphs,
            .cmple, .cmplo, .cmpls, .cmplt, .cmpne, .match, .nmatch,
        ]
        for m in writers {
            #expect(SVEIntegerSemanticAttributes.expectedFlagEffect(for: m) == .nzcv)
        }
        for m in [Mnemonic.add, .adclb, .adclt, .sbclb, .sbclt, .sqadd, .uqsub, .histcnt, .sclamp] {
            #expect(SVEIntegerSemanticAttributes.expectedFlagEffect(for: m) == .none, "\(m.rawValue)")
        }
    }

    @Test func exactlyTheNineteenPreservingMnemonicsPreserveTheirDestination() {
        let preserving: [Mnemonic] = [
            .addhnt, .raddhnt, .subhnt, .rsubhnt,
            .shrnt, .rshrnt, .sqshrnt, .sqrshrnt, .uqshrnt, .uqrshrnt,
            .sqshrunt, .sqrshrunt, .sqxtnt, .sqxtunt, .uqxtnt,
            .eorbt, .eortb, .sli, .sri,
        ]
        #expect(preserving.count == 19)
        for m in preserving {
            #expect(SVEIntegerSemanticAttributes.preservesDestination(m), "\(m.rawValue)")
        }
        // The bottoms, the accumulators and the widening tops all rewrite
        // every lane — none of them preserve.
        for m in [Mnemonic.addhnb, .shrnb, .sqxtnb, .ssra, .smlalt, .ushllt, .sclamp, .add] {
            #expect(!SVEIntegerSemanticAttributes.preservesDestination(m), "\(m.rawValue)")
        }
    }

    @Test func theDestinationReadersSpanAccumulatorsClampsAndPreservers() {
        let readers: [Mnemonic] = [
            .sdot, .udot, .usdot, .sudot, .cdot, .smmla, .ummla, .usmmla,
            .mla, .mls, .sqrdmlah, .sqrdmlsh, .cmla, .sqrdcmlah,
            .smlalb, .umlslt, .sqdmlalbt, .mlapt, .madpt,
            .ssra, .ursra, .saba, .uabalt, .adclb, .sbclt, .sadalp, .uadalp,
            .sclamp, .uclamp, .sli, .sqxtnt,
        ]
        for m in readers {
            #expect(SVEIntegerSemanticAttributes.readsDestination(m), "\(m.rawValue)")
        }
        // The destructive two-address forms are deliberately absent: their
        // destination already appears among the source operands.
        for m in [Mnemonic.add, .and, .asr, .mul, .sub, .xar, .eor3, .mov, .saddlb] {
            #expect(!SVEIntegerSemanticAttributes.readsDestination(m), "\(m.rawValue)")
        }
    }

    @Test func theRegisterMaskWeighsEveryOperandKind() {
        let mask = SVEIntegerSemanticAttributes.registerMask
        #expect(mask(.register(.x(3))) == 1 << 3)
        #expect(mask(.register(.sp())) == 1 << 31, "the stack pointer stays in the mask")
        #expect(mask(.register(.xzr())) == 0, "the zero register is dropped")
        #expect(mask(.scalableVector(ScalableVectorRef(registerIndex: 4))) == 1 << 36)
        #expect(mask(.vectorRegister(VectorRegisterRef(registerIndex: 4, view: .scalar(size: .d)))) == 1 << 36)
        let group = ScalableVectorGroup(firstIndex: 30, count: 2, element: .h, layout: .consecutive)
        #expect(mask(.scalableVectorGroup(group)) == (UInt64(1) << 62) | (UInt64(1) << 63))
        let memory = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: 1, element: .d)),
            index: ScalableVectorRef(registerIndex: 2, element: .d),
            indexExtend: .sxtw, scaleShift: 0,
        )
        #expect(mask(.scalableMemory(memory)) == (1 << 33) | (1 << 34))
        let gprBased = ScalableMemoryOperand(
            base: .gpr(.x(0)), index: nil, indexExtend: .lsl, scaleShift: 0,
        )
        #expect(mask(.scalableMemory(gprBased)) == 0, "a GPR base is not a scalable register")
        #expect(mask(.immediate(value: 1, width: 8)) == 0)
        #expect(mask(.scalablePredicate(ScalablePredicateRef(registerIndex: 1))) == 0)
    }

    @Test func thePredicateWalkFollowsRolesAndTheMergingRule() {
        let result = Operand.scalablePredicate(
            ScalablePredicateRef(registerIndex: 3, element: .s, role: .result),
        )
        let zeroing = Operand.scalablePredicate(
            ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing),
        )
        let merging = Operand.scalablePredicate(
            ScalablePredicateRef(registerIndex: 1, qualifier: .merging, role: .governing),
        )
        #expect(SVEIntegerSemanticAttributes.expectedPredicateWrites([result, zeroing]) == 0b1000)
        #expect(SVEIntegerSemanticAttributes.expectedPredicateWrites([zeroing]) == 0)
        #expect(SVEIntegerSemanticAttributes.expectedPredicateReads([result, zeroing]) == 0b0010)
        // Under a merging predicate the result predicate is an RMW source —
        // the structural invariant, even though no current integer form
        // combines the two.
        #expect(SVEIntegerSemanticAttributes.expectedPredicateReads([result, merging]) == 0b1010)
        #expect(SVEIntegerSemanticAttributes.hasMergingGoverning([merging]))
        #expect(!SVEIntegerSemanticAttributes.hasMergingGoverning([zeroing, result]))
    }

    @Test func theMaskDerivationsSurviveAnOperandlessRecord() {
        // A decoder bug that emitted a named mnemonic with no operands must
        // be reported as the mismatch it is, not trap the sweep on an empty
        // operand range.
        let empty = Instruction(
            address: 0, encoding: 0, mnemonic: .add, category: .sve,
            scalableEffect: .readsStreamingMode,
        )
        #expect(SVEIntegerSemanticAttributes.expectedRegisterWrites(for: empty) == 0)
        #expect(SVEIntegerSemanticAttributes.expectedRegisterReads(for: empty) == 0)
        #expect(SVEIntegerSemanticChecker.verify(draft: empty) == nil, "empty masks match empty operands")
    }

    @Test func theExpectedMasksMatchAHandComputedForm() {
        // smlalb z3.s, z5.h, z9.h — accumulator: writes Z3, reads Z3+Z5+Z9.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .smlalb, category: .sve,
            operands: [
                .scalableVector(ScalableVectorRef(registerIndex: 3, element: .s)),
                .scalableVector(ScalableVectorRef(registerIndex: 5, element: .h)),
                .scalableVector(ScalableVectorRef(registerIndex: 9, element: .h)),
            ],
        )
        #expect(SVEIntegerSemanticAttributes.expectedRegisterWrites(for: draft) == 1 << 35)
        #expect(
            SVEIntegerSemanticAttributes.expectedRegisterReads(for: draft)
                == (1 << 35) | (1 << 37) | (1 << 41),
        )
    }
}

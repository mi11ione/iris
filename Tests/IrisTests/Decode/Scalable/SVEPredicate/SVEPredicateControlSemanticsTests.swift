// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func verify(_ draft: Instruction) -> SVEPCSemanticIssue? {
    SVEPredicateControlSemanticChecker.verify(draft: draft)
}

/// Validates the semantic-attribute checker field by field.
@Suite("SVE predicate & control / semantic-attribute checker")
struct SVEPredicateControlSemanticCheckerTests {
    @Test func aWellFormedRecordFromEveryGroupPasses() {
        let representatives: [UInt32] = [
            0x2518_E000,
            0x2519_E3E0,
            0x2518_E407,
            0x2550_C440,
            0x2503_4820,
            0x2543_4820,
            0x2503_4A30,
            0x2584_5081,
            0x2505_4A75,
            0x2507_5E41,
            0x2510_4443,
            0x2510_4453,
            0x2518_4443,
            0x2504_C443,
            0x2558_C043,
            0x2519_C443,
            0x2518_F043,
            0x2519_F003,
            0x2528_9040,
            0x252C_9000,
            0x2520_8443,
            0x256C_8043,
            0x2568_8843,
            0x2569_8843,
            0x2525_04C7,
            0x2525_30C7,
            0x25A5_20C0,
            0x0420_E3E0,
            0x0430_E3E4,
            0x0420_F3E1,
            0x0460_C3E2,
            0x0421_50A2,
            0x043F_579F,
            0x0421_58A2,
            0x04BF_5020,
            0x04BF_5FE0,
            0x0423_4020,
            0x04E6_4CA3,
            0x0420_BC20,
            0x0450_2C20,
            0x0491_3C20,
        ]
        for encoding in representatives {
            #expect(verify(decode(encoding)) == nil, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func anUndefinedRecordHasNoAttributesToCheck() {
        #expect(verify(decode(0x2543_4A30)) == nil)
    }

    @Test func aRecordFromTheWrongCategoryIsRejected() {
        let d = perturbing(decode(0x2518_E000)) {
            $0.category = .simdAndFP
        }
        #expect(verify(d)?.field == "category")
    }

    @Test func aRecordClaimingToBranchIsRejected() {
        let d = perturbing(decode(0x2518_E000)) {
            $0.branchClass = .indirect
        }
        #expect(verify(d)?.field == "branchClass")
    }

    @Test func aRecordClaimingToTouchMemoryIsRejected() {
        let d = perturbing(decode(0x2518_E000)) {
            $0.memoryAccess = .load
        }
        #expect(verify(d)?.field == "memoryAccess")

        let ordered = perturbing(decode(0x2518_E000)) {
            $0.memoryOrdering = [.acquire]
        }
        #expect(verify(ordered)?.field == "memoryOrdering")
    }

    @Test func aWrongFlagEffectIsRejected() {
        let invented = perturbing(decode(0x2518_E000)) {
            $0.flagEffect = .nzcv
        }
        let issue = verify(invented)
        #expect(issue?.field == "flagEffect")
        #expect(issue?.actual == "\(FlagEffect.nzcv.rawValue)")
        #expect(issue?.expected == "\(FlagEffect.none.rawValue)")

        let dropped = perturbing(decode(0x2519_E3E0)) {
            $0.flagEffect = .none
        }
        #expect(verify(dropped)?.field == "flagEffect")
    }

    @Test func aConditionalTerminateWithAPlainFlagWriteIsRejected() {
        let d = perturbing(decode(0x25A5_20C0)) {
            $0.flagEffect = .nzcv
        }
        #expect(verify(d)?.field == "flagEffect")
    }

    @Test func aWrongScalableEffectIsRejected() {
        let dropped = perturbing(decode(0x2518_E000)) {
            $0.scalableEffect = .none
        }
        #expect(verify(dropped)?.field == "scalableEffect")

        let invented = perturbing(decode(0x25A5_20C0)) {
            $0.scalableEffect = .readsStreamingMode
        }
        #expect(verify(invented)?.field == "scalableEffect")
    }

    @Test func aMissingPartialWriteOnAMergingFormIsRejected() {
        for encoding: UInt32 in [0x2510_4453, 0x2590_4453, 0x2558_C043, 0x0491_3C20] {
            let d = perturbing(decode(encoding)) {
                $0.scalableEffect = .readsStreamingMode
            }
            #expect(verify(d)?.field == "scalableEffect", "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func anInventedPartialWriteIsRejected() {
        for encoding: UInt32 in [0x2510_4443, 0x2505_4A75, 0x0450_2C20, 0x2519_C443] {
            let d = perturbing(decode(encoding)) {
                $0.scalableEffect = [.readsStreamingMode, .partialWrite]
            }
            #expect(verify(d)?.field == "scalableEffect", "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func aWrongFirstFaultReadIsRejected() {
        let invented = perturbing(decode(0x2518_E000)) {
            $0.scalableReads = $0.scalableReads.insertingFFR()
        }
        #expect(verify(invented)?.field == "ffrRead")

        let dropped = perturbing(decode(0x2518_F043)) {
            $0.scalableReads = ScalableRegisterSet.empty.insertingPredicate(2)
        }
        #expect(verify(dropped)?.field == "ffrRead")
    }

    @Test func aWrongFirstFaultWriteIsRejected() {
        let invented = perturbing(decode(0x2518_E000)) {
            $0.scalableWrites = $0.scalableWrites.insertingFFR()
        }
        #expect(verify(invented)?.field == "ffrWrite")

        let dropped = perturbing(decode(0x252C_9000)) {
            $0.scalableWrites = .empty
        }
        #expect(verify(dropped)?.field == "ffrWrite")
    }

    @Test func aWrongPredicateWriteMaskIsRejected() {
        let d = perturbing(decode(0x2518_E000)) {
            $0.scalableWrites = ScalableRegisterSet.empty.insertingPredicate(5)
        }
        let issue = verify(d)
        #expect(issue?.field == "predicateWrites")
        #expect(issue?.actual == "0x20")
        #expect(issue?.expected == "0x1")
    }

    @Test func aWrongPredicateReadMaskIsRejected() {
        let d = perturbing(decode(0x2518_E000)) {
            $0.scalableReads = ScalableRegisterSet.empty.insertingPredicate(3)
        }
        let issue = verify(d)
        #expect(issue?.field == "predicateReads")
        #expect(issue?.actual == "0x8")
        #expect(issue?.expected == "0x0")
    }

    @Test func aMergingFormThatForgetsToReadItsDestinationIsRejected() {
        let d = perturbing(decode(0x2510_4453)) {
            $0.scalableReads = ScalableRegisterSet.empty.insertingPredicate(1).insertingPredicate(2)
        }
        #expect(verify(d)?.field == "predicateReads")
    }

    @Test func aWrongRegisterWriteMaskIsRejected() {
        let d = perturbing(decode(0x2520_8443)) {
            $0.semanticWrites = .empty
        }
        let issue = verify(d)
        #expect(issue?.field == "registerWrites")
        #expect(issue?.expected == "0x8")
    }

    @Test func aWrongRegisterReadMaskIsRejected() {
        let d = perturbing(decode(0x2520_8443)) {
            $0.semanticReads = RegisterSet.empty.inserting(.x(7))
        }
        let issue = verify(d)
        #expect(issue?.field == "registerReads")
        #expect(issue?.actual == "0x80")
        #expect(issue?.expected == "0x0")
    }

    @Test func anAccumulateFormThatForgetsToReadItsDestinationIsRejected() {
        let d = perturbing(decode(0x0430_E3E4)) {
            $0.semanticReads = .empty
        }
        #expect(verify(d)?.field == "registerReads")
    }

    @Test func aStackPointerAdjustThatDropsItsSourceIsRejected() {
        let d = perturbing(decode(0x043F_579F)) {
            $0.semanticReads = .empty
        }
        #expect(verify(d)?.field == "registerReads")
    }

    @Test func aSemanticIssueCarriesItsThreeFieldsAndComparesByValue() {
        let issue = SVEPCSemanticIssue(field: "flagEffect", actual: "0", expected: "15")
        #expect(issue.field == "flagEffect")
        #expect(issue.actual == "0")
        #expect(issue.expected == "15")
        #expect(issue == SVEPCSemanticIssue(field: "flagEffect", actual: "0", expected: "15"))
        #expect(issue != SVEPCSemanticIssue(field: "flagEffect", actual: "15", expected: "0"))
    }
}

/// Validates the per-mnemonic attribute tables the checker derives its
/// expectations from.
@Suite("SVE predicate & control / semantic-attribute tables")
struct SVEPredicateControlSemanticAttributeTests {
    @Test func everyFlagSettingFormIsListed() {
        let nzcv: [Mnemonic] = [
            .ptrues, .ptest, .pfirst, .pnext,
            .ands, .bics, .eors, .orrs, .orns, .nands, .nors, .movs, .nots,
            .brkas, .brkbs, .brkns, .brkpas, .brkpbs, .rdffrs,
            .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi,
            .whilelo, .whilels, .whilerw, .whilewr,
        ]
        for m in nzcv {
            #expect(
                SVEPredicateControlSemanticAttributes.expectedFlagEffect(for: m) == .nzcv,
                "\(m.rawValue) must write NZCV",
            )
        }
    }

    @Test func conditionalTerminateHasItsOwnFlagSet() {
        for m in [Mnemonic.ctermeq, .ctermne] {
            #expect(
                SVEPredicateControlSemanticAttributes.expectedFlagEffect(for: m)
                    == [.writesN, .writesV, .readsC],
            )
        }
    }

    @Test func theRemainingFormsTouchNoFlag() {
        let quiet: [Mnemonic] = [
            .ptrue, .pfalse, .and, .bic, .eor, .orr, .orn, .nand, .nor, .sel, .mov, .not,
            .brka, .brkb, .brkn, .brkpa, .brkpb, .rdffr, .wrffr, .setffr,
            .cntp, .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp,
            .cntb, .incb, .decb, .sqincb, .uqincb, .sqdecb, .uqdecb,
            .rdvl, .rdsvl, .addvl, .addsvl, .addpl, .addspl, .index, .movprfx,
        ]
        for m in quiet {
            #expect(
                SVEPredicateControlSemanticAttributes.expectedFlagEffect(for: m) == .none,
                "\(m.rawValue) must write no flag",
            )
        }
    }

    @Test func onlyTheFirstFaultInstructionsTouchTheFirstFaultRegister() {
        #expect(SVEPredicateControlSemanticAttributes.expectedFFR(for: .rdffr) == (true, false))
        #expect(SVEPredicateControlSemanticAttributes.expectedFFR(for: .rdffrs) == (true, false))
        #expect(SVEPredicateControlSemanticAttributes.expectedFFR(for: .wrffr) == (false, true))
        #expect(SVEPredicateControlSemanticAttributes.expectedFFR(for: .setffr) == (false, true))
        for m in [Mnemonic.ptrue, .cntp, .whilelt, .movprfx, .index] {
            #expect(SVEPredicateControlSemanticAttributes.expectedFFR(for: m) == (false, false))
        }
    }

    @Test func thePredicateWriteMaskIsTheResultOperands() {
        let ops: Instruction.Operands = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 4, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ]
        #expect(SVEPredicateControlSemanticAttributes.expectedPredicateWrites(ops) == 1 << 4)
        #expect(SVEPredicateControlSemanticAttributes.expectedPredicateReads(ops) == (1 << 1) | (1 << 2))
    }

    @Test func aMergingGoverningPredicateAddsTheDestinationToTheReads() {
        let ops: Instruction.Operands = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 4, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .merging, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ]
        #expect(
            SVEPredicateControlSemanticAttributes.expectedPredicateReads(ops)
                == (1 << 1) | (1 << 2) | (1 << 4),
        )
    }

    @Test func operandsThatAreNotPredicatesContributeNothing() {
        let ops: Instruction.Operands = [.register(.x(3)), .immediate(value: 1, width: 5)]
        #expect(SVEPredicateControlSemanticAttributes.expectedPredicateWrites(ops) == 0)
        #expect(SVEPredicateControlSemanticAttributes.expectedPredicateReads(ops) == 0)
    }

    @Test func theOperandRegisterMaskReadsTheCanonicalIndex() {
        let ops: Instruction.Operands = [
            .register(.x(3)),
            .register(.sp()),
            .register(.xzr()),
            .scalableVector(ScalableVectorRef(registerIndex: 2)),
            .immediate(value: 7, width: 5),
        ]
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 0) == 1 << 3)
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 1) == 1 << 31)
        #expect(
            SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 2) == 0,
            "the zero register is not a dependency",
        )
        #expect(
            SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 3) == 1 << 34,
            "a scalable vector shares its bit with the NEON view of the same register",
        )
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 4) == 0)
    }

    @Test func theOperandRegisterMaskIsBoundsChecked() {
        let ops: Instruction.Operands = [.register(.x(1))]
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, -1) == 0)
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask(ops, 1) == 0)
        #expect(SVEPredicateControlSemanticAttributes.operandRegisterMask([], 0) == 0)
    }

    @Test func theRegisterWriteMaskIsTheDestinationOperandOnlyForTheFormsThatHaveOne() {
        let counted = decode(0x2520_8443)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterWrites(for: counted) == 1 << 3)

        let predicateOnly = decode(0x2518_E000)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterWrites(for: predicateOnly) == 0)

        let compared = decode(0x25A5_20C0)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterWrites(for: compared) == 0)
    }

    @Test func theRegisterReadMaskFollowsEachFormsOperandOrder() {
        let loop = decode(0x25E5_14C7)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: loop) == (1 << 6) | (1 << 5))

        let compare = decode(0x25E5_20D0)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: compare) == (1 << 6) | (1 << 5))

        let adjust = decode(0x0421_50A2)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: adjust) == 1 << 1)

        let accumulate = decode(0x0430_E3E4)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: accumulate) == 1 << 4)

        let generated = decode(0x0423_4020)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: generated) == 0)

        let read = decode(0x04BF_5020)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: read) == 0)
    }

    @Test func theConstructivePrefixReadsItsDestinationOnlyWhenMerging() {
        let unpredicated = decode(0x0420_BC20)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: unpredicated) == 1 << 33)

        let zeroing = decode(0x0450_2C20)
        #expect(SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: zeroing) == 1 << 33)

        let merging = decode(0x0491_3C20)
        #expect(
            SVEPredicateControlSemanticAttributes.expectedRegisterReads(for: merging)
                == (1 << 32) | (1 << 33),
        )
    }
}

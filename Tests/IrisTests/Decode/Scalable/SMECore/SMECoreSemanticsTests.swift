// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func field(_ draft: Instruction) -> String? {
    SMECoreSemanticChecker.verify(draft: draft)?.field
}

private func perturbed(_ encoding: UInt32, _ body: (inout InstructionImage) -> Void) -> SMECoreSemanticIssue? {
    SMECoreSemanticChecker.verify(draft: perturbing(decode(encoding), body))
}

private let familyRepresentatives: [(UInt32, String)] = [
    (0x8080_0000, "fmopa — outer product .s"),
    (0x80C0_0000, "fmopa — outer product .d"),
    (0x8180_0008, "fmopa — outer product .h"),
    (0xA1E0_0010, "umops — integer outer product"),
    (0x8080_0008, "bmopa — binary outer product"),
    (0xC090_0000, "addha .s"),
    (0xC0D1_0000, "addva .d"),
    (0xC000_0000, "mov — MOVA insert"),
    (0xC0C3_0000, "mov — MOVA extract .q"),
    (0xC008_00A5, "zero — generic .d list"),
    (0xC008_00FF, "zero — whole array"),
    (0xE01F_0000, "ld1b — no index"),
    (0xE1C0_0000, "ld1q — indexed"),
    (0xE03F_0000, "st1b — no index"),
    (0xE1E0_0000, "st1q — indexed"),
    (0xE100_0000, "ldr za"),
    (0xE120_0000, "str za"),
]

/// Validates that the independently-derived semantic model agrees with every
/// record the decoder produces.
@Suite("SME core semantics / consistent records pass")
struct SMECoreSemanticsPassTests {
    @Test func everyFamilyRepresentativePassesTheChecker() {
        for (encoding, label) in familyRepresentatives {
            #expect(SMECoreSemanticChecker.verify(draft: decode(encoding)) == nil, "\(label)")
        }
    }

    @Test func anUndefinedRecordIsVacuouslyValid() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .undefined,
            branchClass: .exception, memoryAccess: .load, category: .undefined,
            scalableEffect: [.writesStreamingMode],
        )
        #expect(SMECoreSemanticChecker.verify(draft: draft) == nil)
    }

    @Test func theMemoryKindFollowsTheFamily() {
        #expect(decode(0xE01F_0000).memoryAccess == .load)
        #expect(decode(0xE03F_0000).memoryAccess == .store)
        #expect(decode(0xE100_0000).memoryAccess == .load)
        #expect(decode(0xE120_0000).memoryAccess == .store)
        #expect(decode(0x8080_0000).memoryAccess == .none)
        #expect(decode(0xC008_0011).memoryAccess == .none)
    }
}

/// Validates that the checker reports a record rendering plausibly but
/// mis-tagging its semantics; each case perturbs one attribute so the
/// reported.
@Suite("SME core semantics / mismatches are reported")
struct SMECoreSemanticsMismatchTests {
    @Test func aForeignCategoryIsReported() {
        let issue = perturbed(0x8080_0000) { $0.category = .simdAndFP }
        #expect(issue?.field == "category")
        #expect(issue?.actual == "\(Category.simdAndFP.rawValue)")
        #expect(issue?.expected == "\(Category.sme.rawValue)")
    }

    @Test func aBranchClassIsReported() {
        #expect(perturbed(0x8080_0000) { $0.branchClass = .exception }?.field == "branchClass")
    }

    @Test func aFlagEffectIsReported() {
        #expect(perturbed(0x8080_0000) { $0.flagEffect = .writesN }?.field == "flagEffect")
    }

    @Test func aMemoryOrderingIsReported() {
        let issue = perturbed(0xE01F_0000) { $0.memoryOrdering = .acquire }
        #expect(issue?.field == "memoryOrdering")
        #expect(issue?.expected == "0")
    }

    @Test func anUnknownMnemonicIsReported() {
        let draft = Instruction(address: 0, encoding: 0, mnemonic: .add, category: .sme)
        let issue = SMECoreSemanticChecker.verify(draft: draft)
        #expect(issue?.field == "family")
        #expect(issue?.actual == "\(Mnemonic.add.rawValue)")
    }

    @Test func aWrongMemoryKindIsReported() {
        #expect(perturbed(0xE01F_0000) { $0.memoryAccess = .none }?.field == "memoryAccess")
        #expect(perturbed(0xE01F_0000) { $0.memoryAccess = .store }?.field == "memoryAccess")
        #expect(perturbed(0x8080_0000) { $0.memoryAccess = .load }?.field == "memoryAccess")
        #expect(perturbed(0xE120_0000) { $0.memoryAccess = .load }?.field == "memoryAccess")
    }

    @Test func aMissingStreamingFlagIsReported() {
        let issue = perturbed(0x8080_0000) { $0.scalableEffect = [.partialWrite] }
        #expect(issue?.field == "readsStreamingMode")
        #expect(issue?.actual == "unset")
        #expect(issue?.expected == "set")
    }

    @Test func aSpuriousStreamingFlagOnANonStreamingFormIsReported() {
        let issue = perturbed(0xE120_0000) { $0.scalableEffect = [.readsStreamingMode] }
        #expect(issue?.field == "readsStreamingMode")
        #expect(issue?.actual == "set")
        #expect(issue?.expected == "unset")
        #expect(perturbed(0xC008_0011) { $0.scalableEffect = [.readsStreamingMode] }?.field == "readsStreamingMode")
    }

    @Test func aMissingPartialWriteIsReported() {
        #expect(perturbed(0x8080_0000) { $0.scalableEffect = [.readsStreamingMode] }?.field == "partialWrite")
        #expect(perturbed(0xE100_0000) { $0.scalableEffect = .none }?.field == "partialWrite")
    }

    @Test func aSpuriousPartialWriteOnAnExactWriteIsReported() {
        let issue = perturbed(0xC008_0011) { $0.scalableEffect = [.partialWrite] }
        #expect(issue?.field == "partialWrite")
        #expect(perturbed(0xE120_0000) { $0.scalableEffect = [.partialWrite] }?.field == "partialWrite")
        #expect(perturbed(0xE03F_0000) { $0.scalableEffect = [.readsStreamingMode, .partialWrite] }?.field == "partialWrite")
    }

    @Test func aStreamingModeWriteIsReported() {
        let issue = perturbed(0x8080_0000) { $0.scalableEffect.insert(.writesStreamingMode) }
        #expect(issue?.field == "writesStreamingMode")
        #expect(issue?.actual == "set")
        #expect(issue?.expected == "unset")
    }

    @Test func aZAEnableWriteIsReported() {
        let issue = perturbed(0x8080_0000) { $0.scalableEffect.insert(.writesZAEnable) }
        #expect(issue?.field == "writesZAEnable")
    }

    @Test func aWrongZAReadMaskIsReported() {
        let issue = perturbed(0x8080_0000) {
            $0.scalableReads = $0.scalableReads.inserting(ZATileMask(tile: 1, element: .s))
        }
        #expect(issue?.field == "scalableReads.za")
        #expect(issue?.expected == "0x1111")
        #expect(issue?.actual == "0x3333")
    }

    @Test func aWrongZAWriteMaskIsReported() {
        let issue = perturbed(0xC008_0011) {
            $0.scalableWrites = ScalableRegisterSet.empty.inserting(.whole)
        }
        #expect(issue?.field == "scalableWrites.za")
        #expect(issue?.actual == "0xffff")
        #expect(issue?.expected == "0x1111")
    }

    @Test func aDroppedZAWriteOnALoadIsReported() {
        #expect(perturbed(0xE01F_0000) { $0.scalableWrites = .empty }?.field == "scalableWrites.za")
        #expect(perturbed(0xE100_0000) { $0.scalableWrites = .empty }?.field == "scalableWrites.za")
    }

    @Test func aDroppedZAReadOnAStoreIsReported() {
        #expect(perturbed(0xE03F_0000) { $0.scalableReads = .empty }?.field == "scalableReads.za")
        #expect(perturbed(0xE120_0000) { $0.scalableReads = .empty }?.field == "scalableReads.za")
    }

    @Test func aDroppedSelectRegisterReadIsReported() {
        for encoding: UInt32 in [0xE01F_0000, 0xE03F_0000, 0xC000_0000, 0xC002_0000, 0xE100_0000, 0xE120_0000] {
            let issue = perturbed(encoding) { $0.semanticReads = .empty }
            #expect(issue?.field == "semanticReads.selectRegister", "0x\(String(encoding, radix: 16))")
            #expect(issue?.actual == "missing w12")
            #expect(issue?.expected == "w12 read")
        }
    }

    @Test func aMovaExtractIsToldFromAnInsertByItsFirstOperand() {
        let draft = perturbing(decode(0xC000_0000)) { $0.operands.reverse() }
        #expect(field(draft) == "scalableWrites.za")
    }
}

/// Validates that the checker stays total over records the decoder never
/// produces.
@Suite("SME core semantics / total over unexpected operand shapes")
struct SMECoreSemanticsTotalityTests {
    private func draft(
        mnemonic: Mnemonic,
        operands: [Operand] = [],
        scalableReads: ScalableRegisterSet = .empty,
        scalableWrites: ScalableRegisterSet = .empty,
        scalableEffect: ScalableEffect = [.readsStreamingMode, .partialWrite],
    ) -> Instruction {
        Instruction(
            address: 0, encoding: 0, mnemonic: mnemonic, category: .sme, operands: operands,
            scalableReads: scalableReads, scalableWrites: scalableWrites, scalableEffect: scalableEffect,
        )
    }

    @Test func anOuterProductWithoutAZAOperandExpectsAnEmptyMask() {
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .fmopa)) == nil)
        let mismatch = draft(
            mnemonic: .fmopa,
            scalableWrites: ScalableRegisterSet.empty.inserting(.whole),
        )
        #expect(field(mismatch) == "scalableWrites.za")
    }

    @Test func aMovWithoutOperandsClassifiesAsAnExtractWithNoTile() {
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .mov)) == nil)
    }

    @Test func aZAOperandBehindOtherOperandsIsStillFound() {
        let operands: [Operand] = [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0, qualifier: .merging)),
            .zaArrayVector(ZAArrayVectorOperand(selectRegister: .w(12), offset: 0)),
        ]
        let whole = ScalableRegisterSet.empty.inserting(.whole)
        let record = draft(
            mnemonic: .addha, operands: operands,
            scalableReads: whole, scalableWrites: whole,
        )
        #expect(SMECoreSemanticChecker.verify(draft: record) == nil)
    }

    @Test func aSuffixLessTileOperandCoversTheWholeArray() {
        let whole = ScalableRegisterSet.empty.inserting(.whole)
        let record = draft(
            mnemonic: .addha, operands: [.zaTile(index: 0, element: nil)],
            scalableReads: whole, scalableWrites: whole,
        )
        #expect(SMECoreSemanticChecker.verify(draft: record) == nil)
        let narrowed = draft(
            mnemonic: .addha, operands: [.zaTile(index: 0, element: nil)],
            scalableReads: ScalableRegisterSet.empty.inserting(ZATileMask(tile: 0, element: .s)),
            scalableWrites: whole,
        )
        #expect(field(narrowed) == "scalableReads.za")
    }

    @Test func aZeroWithoutTileOperandsExpectsAnEmptyWrite() {
        let operands: [Operand] = [.scalablePredicate(ScalablePredicateRef(registerIndex: 0))]
        let record = draft(mnemonic: .zero, operands: operands, scalableEffect: .none)
        #expect(SMECoreSemanticChecker.verify(draft: record) == nil)
    }

    @Test func aZeroTileListMixesSizedAndWholeArrayEntries() {
        let operands: [Operand] = [
            .zaTile(index: 0, element: .s),
            .zaTile(index: 0, element: nil),
        ]
        let record = draft(
            mnemonic: .zero, operands: operands,
            scalableWrites: ScalableRegisterSet.empty.inserting(.whole),
            scalableEffect: .none,
        )
        #expect(SMECoreSemanticChecker.verify(draft: record) == nil)
    }

    @Test func aRecordWithNoSelectRegisterSkipsTheSelectCheck() {
        let operands: [Operand] = [.scalableVector(ScalableVectorRef(registerIndex: 0, element: .b))]
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .mov, operands: operands)) == nil)
    }
}

/// Validates the `SMECoreSemanticIssue` value.
@Suite("SME core semantics / issue value")
struct SMECoreSemanticIssueTests {
    @Test func theIssueCarriesItsThreeFields() {
        let issue = SMECoreSemanticIssue(field: "scalableWrites.za", actual: "0x1111", expected: "0x3333")
        #expect(issue.field == "scalableWrites.za")
        #expect(issue.actual == "0x1111")
        #expect(issue.expected == "0x3333")
    }

    @Test func equalIssuesHashEqual() {
        let a = SMECoreSemanticIssue(field: "partialWrite", actual: "set", expected: "unset")
        let b = SMECoreSemanticIssue(field: "partialWrite", actual: "set", expected: "unset")
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
        #expect(Set([a, b]).count == 1)
    }

    @Test func differingIssuesAreDistinct() {
        let a = SMECoreSemanticIssue(field: "partialWrite", actual: "set", expected: "unset")
        #expect(a != SMECoreSemanticIssue(field: "readsStreamingMode", actual: "set", expected: "unset"))
        #expect(a != SMECoreSemanticIssue(field: "partialWrite", actual: "unset", expected: "unset"))
        #expect(a != SMECoreSemanticIssue(field: "partialWrite", actual: "set", expected: "set"))
    }
}

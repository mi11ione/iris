// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0, features: .scalable)
}

private func field(_ draft: Instruction) -> String? {
    SMECoreSemanticChecker.verify(draft: draft)?.field
}

/// Decode `encoding`, perturb exactly one field of the resulting record, and
/// report which check fires. Starting from a record the decoder really produced
/// keeps every other attribute self-consistent, so the reported field pins the
/// perturbation rather than an incidental second violation.
private func perturbed(_ encoding: UInt32, _ body: (inout InstructionImage) -> Void) -> SMECoreSemanticIssue? {
    SMECoreSemanticChecker.verify(draft: perturbing(decode(encoding), body))
}

/// One representative encoding per family the checker classifies.
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
/// record the decoder produces. The checker re-derives the memory-access kind,
/// the streaming and partial-write flags, the `ZA` overlap masks and the
/// select-register read from the mnemonic and operand shape alone, so a record
/// that renders perfect text but mis-tags any of them is still caught. Each
/// family is represented because the derivation branches per family, and the
/// `mov` token is represented twice because its two directions are told apart
/// only by which operand comes first.
@Suite("SME core semantics / consistent records pass")
struct SMECoreSemanticsPassTests {
    @Test func everyFamilyRepresentativePassesTheChecker() {
        for (encoding, label) in familyRepresentatives {
            #expect(SMECoreSemanticChecker.verify(draft: decode(encoding)) == nil, "\(label)")
        }
    }

    @Test func anUndefinedRecordIsVacuouslyValid() {
        // An UNDEFINED carries no semantic content, so the checker
        // short-circuits before any invariant could contradict it.
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

/// Validates that the checker actually reports a record that renders plausibly
/// but mis-tags its semantics. Each case starts from a real decode and perturbs
/// exactly one attribute, so the reported field name pins which invariant fired
/// — a checker that silently accepted any of these would let the validator's
/// semantic sweep pass over a real classification bug.
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
        // No SME-core instruction touches NZCV.
        #expect(perturbed(0x8080_0000) { $0.flagEffect = .writesN }?.field == "flagEffect")
    }

    @Test func aMemoryOrderingIsReported() {
        let issue = perturbed(0xE01F_0000) { $0.memoryOrdering = .acquire }
        #expect(issue?.field == "memoryOrdering")
        #expect(issue?.expected == "0")
    }

    @Test func anUnknownMnemonicIsReported() {
        // A record tagged `.sme` whose mnemonic belongs to no 2s.6 family is a
        // decoder that leaked another tier's token into this category.
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
        // LDR/STR ZA and ZERO are safe outside streaming mode; claiming
        // otherwise would make Piece 4 insert a mode requirement that is not
        // architecturally there.
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
        // ZERO is the one exact full-def in 2s.6; marking it partial would
        // block a legitimate liveness kill.
        let issue = perturbed(0xC008_0011) { $0.scalableEffect = [.partialWrite] }
        #expect(issue?.field == "partialWrite")
        #expect(perturbed(0xE120_0000) { $0.scalableEffect = [.partialWrite] }?.field == "partialWrite")
        #expect(perturbed(0xE03F_0000) { $0.scalableEffect = [.readsStreamingMode, .partialWrite] }?.field == "partialWrite")
    }

    @Test func aStreamingModeWriteIsReported() {
        // Only the 2.3 SMSTART/SMSTOP records transition streaming mode.
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
        // `Wv` appears in the text as a register name inside the slice
        // brackets, but only the read set makes it visible to dataflow.
        for encoding: UInt32 in [0xE01F_0000, 0xE03F_0000, 0xC000_0000, 0xC002_0000, 0xE100_0000, 0xE120_0000] {
            let issue = perturbed(encoding) { $0.semanticReads = .empty }
            #expect(issue?.field == "semanticReads.selectRegister", "0x\(String(encoding, radix: 16))")
            #expect(issue?.actual == "missing w12")
            #expect(issue?.expected == "w12 read")
        }
    }

    @Test func aMovaExtractIsToldFromAnInsertByItsFirstOperand() {
        // The two directions share the `mov` token; only the operand order
        // distinguishes them, so an insert's masks must not satisfy an
        // extract's expectation.
        // insert: tile slice first; reversed, a Z vector comes first — an extract
        let draft = perturbing(decode(0xC000_0000)) { $0.operands.reverse() }
        #expect(field(draft) == "scalableWrites.za")
    }
}

/// Validates that the checker stays total over records the 2s.6 decoder never
/// produces. `verify` is called by the validator on whatever a decode returns,
/// so every derivation helper must have a defined answer for an operand list
/// that carries no `ZA` operand, carries one in an unexpected position, or
/// carries a shape from another tier — never a wrong answer dressed as a pass
/// and never a crash.
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
        // No ZA operand means no tile to name, so the expectation is the empty
        // mask rather than an arbitrary default.
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .fmopa)) == nil)
        let mismatch = draft(
            mnemonic: .fmopa,
            scalableWrites: ScalableRegisterSet.empty.inserting(.whole),
        )
        #expect(field(mismatch) == "scalableWrites.za")
    }

    @Test func aMovWithoutOperandsClassifiesAsAnExtractWithNoTile() {
        // `operands.first` is not a tile slice, so the record reads as an
        // extract; with no slice present the expected read mask is empty.
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .mov)) == nil)
    }

    @Test func aZAOperandBehindOtherOperandsIsStillFound() {
        // The mask search scans the whole operand list, so an unexpected
        // leading operand cannot hide the ZA touch behind it.
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
        // `element == nil` names the whole `za`. Outside ZERO's list the mask
        // helper must widen it to every position rather than reading the index
        // as a tile number, which would understate the touched storage.
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
        // The `{za}` entry has no element size and covers the whole array; a
        // sized entry beside it must union, not replace.
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
        // The select check only fires when a ZA operand actually carries a
        // select register; without one there is nothing to require.
        let operands: [Operand] = [.scalableVector(ScalableVectorRef(registerIndex: 0, element: .b))]
        #expect(SMECoreSemanticChecker.verify(draft: draft(mnemonic: .mov, operands: operands)) == nil)
    }
}

/// Validates the `SMECoreSemanticIssue` value itself — the three fields carry
/// the mismatch report to the validator's log, and it composes into sets like
/// every other value type in the record model.
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

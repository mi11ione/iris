// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Every mnemonic the SVE predicate & control decoder can emit, grouped as the
/// encoding tables group them.
private let initialiseAndTest: [Mnemonic] = [.ptrue, .ptrues, .pfalse, .ptest]
private let predicateLogical: [Mnemonic] = [
    .orrs, .eors, .orns, .nand, .nands, .nor, .nors, .sel, .movs, .nots,
]
private let breakAndPartition: [Mnemonic] = [
    .brka, .brkas, .brkb, .brkbs, .brkn, .brkns,
    .brkpa, .brkpas, .brkpb, .brkpbs, .pfirst, .pnext,
]
private let firstFaultRegister: [Mnemonic] = [.rdffr, .rdffrs, .wrffr, .setffr]
private let predicateCount: [Mnemonic] = [
    .cntp, .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp,
]
private let loopPredicates: [Mnemonic] = [
    .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi, .whilelo, .whilels,
    .whilerw, .whilewr, .ctermeq, .ctermne,
]
private let elementCountAndAdjust: [Mnemonic] = [
    .rdvl, .rdsvl, .addvl, .addsvl, .addpl, .addspl,
    .cntb, .cnth, .cntw, .cntd,
    .incb, .inch, .incw, .incd, .decb, .dech, .decw, .decd,
    .sqincb, .sqinch, .sqincw, .sqincd, .uqincb, .uqinch, .uqincw, .uqincd,
    .sqdecb, .sqdech, .sqdecw, .sqdecd, .uqdecb, .uqdech, .uqdecw, .uqdecd,
]
private let indexAndPrefix: [Mnemonic] = [.index, .movprfx]

private let declaredHere: [Mnemonic] =
    initialiseAndTest + predicateLogical + breakAndPartition + firstFaultRegister
        + predicateCount + loopPredicates + elementCountAndAdjust + indexAndPrefix

/// Validates the mnemonic constants this decoder declares. They are the first
/// allocation inside the reserved scalable range, so two things must hold: every
/// new constant sits inside that range (a raw value that strayed into a
/// neighbouring subpiece's range would silently collide with its mnemonic), and
/// the constants are distinct. The predicate forms of AND/ORR/EOR/BIC/ORN, and
/// the MOV/NOT aliases, deliberately reuse the base-instruction constants — the
/// mnemonic is the text token, and the operand shape plus the scalable category
/// tell the two apart — so those must *not* be redeclared here.
@Suite("SVE predicate & control / mnemonic allocations")
struct MnemonicSVEPredicateControlTests {
    private static let scalableRange: ClosedRange<UInt16> = 16384 ... 28671

    @Test func everyDeclaredMnemonicSitsInTheScalableRange() {
        for m in declaredHere {
            #expect(Self.scalableRange.contains(m.rawValue), "\(m.rawValue) is outside the scalable range")
        }
    }

    @Test func theScalableRangeIsTheOneTheSubstrateReserved() {
        let reserved = Mnemonic.allocations.first { $0.label == "SVE / SVE2 tier" }
        #expect(reserved?.range == Self.scalableRange)
    }

    @Test func everyDeclaredMnemonicIsDistinct() {
        let raws = declaredHere.map(\.rawValue)
        #expect(Set(raws).count == raws.count)
        #expect(raws.count == 85)
    }

    @Test func theDeclaredMnemonicsAreContiguousFromTheStartOfTheRange() {
        // The allocation starts at the base of the range and leaves no gaps, so
        // the next subpiece knows exactly where it may begin.
        let raws = declaredHere.map(\.rawValue).sorted()
        #expect(raws.first == Self.scalableRange.lowerBound)
        #expect(raws == Array(16384 ... 16468))
    }

    @Test func theSharedTextTokensAreReusedNotRedeclared() {
        // These mnemonics already existed for the base-instruction forms; the
        // predicate forms and their aliases reuse them, so their raw values must
        // stay in their original subpiece's range.
        for m in [Mnemonic.and, .ands, .orr, .eor, .bic, .bics, .orn, .mov, .not] {
            #expect(!Self.scalableRange.contains(m.rawValue), "\(m.rawValue) was redeclared in the scalable range")
        }
    }

    @Test func eachEncodingGroupContributesItsOwnConstants() {
        // A group that accidentally shared a constant with another would decode
        // to the wrong text; keep the groups provably disjoint.
        let groups = [
            initialiseAndTest, predicateLogical, breakAndPartition, firstFaultRegister,
            predicateCount, loopPredicates, elementCountAndAdjust, indexAndPrefix,
        ]
        var seen = Set<UInt16>()
        for group in groups {
            for m in group {
                #expect(seen.insert(m.rawValue).inserted, "\(m.rawValue) appears in two groups")
            }
        }
        #expect(seen.count == declaredHere.count)
    }
}

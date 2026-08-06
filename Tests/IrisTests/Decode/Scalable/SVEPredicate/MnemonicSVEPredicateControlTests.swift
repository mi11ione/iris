// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

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

/// Validates the mnemonic constants this decoder declares, the first
/// allocation inside the reserved scalable range.
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
        let raws = declaredHere.map(\.rawValue).sorted()
        #expect(raws.first == Self.scalableRange.lowerBound)
        #expect(raws == Array(16384 ... 16468))
    }

    @Test func theSharedTextTokensAreReusedNotRedeclared() {
        for m in [Mnemonic.and, .ands, .orr, .eor, .bic, .bics, .orn, .mov, .not] {
            #expect(!Self.scalableRange.contains(m.rawValue), "\(m.rawValue) was redeclared in the scalable range")
        }
    }

    @Test func eachEncodingGroupContributesItsOwnConstants() {
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

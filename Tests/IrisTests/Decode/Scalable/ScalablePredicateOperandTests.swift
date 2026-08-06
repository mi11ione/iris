// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `ScalablePredicateRef`. The qualifier and role are opcode
/// properties the decoder attaches to the operand — LLVM keeps them in the.
@Suite("ScalablePredicateRef / predicate operand dressing")
struct ScalablePredicateRefTests {
    @Test func bareGoverningPredicateUsesTheDefaults() {
        let ref = ScalablePredicateRef(registerIndex: 0)
        #expect(ref.registerIndex == 0)
        #expect(ref.element == nil)
        #expect(ref.qualifier == .none)
        #expect(ref.role == .governing)
        #expect(!ref.isCounter)
        #expect(ref.elementIndex == nil)
    }

    @Test func registerIndexIsMaskedToFourBits() {
        #expect(ScalablePredicateRef(registerIndex: 16).registerIndex == 0)
        #expect(ScalablePredicateRef(registerIndex: 0xFF).registerIndex == 15)
    }

    @Test func everyPredicateRegisterIsNameable() {
        for index: UInt8 in 0 ... 15 {
            #expect(ScalablePredicateRef(registerIndex: index).registerIndex == index)
        }
    }

    @Test func zeroingGoverningPredicateCarriesItsQualifier() {
        let ref = ScalablePredicateRef(registerIndex: 2, element: .s, qualifier: .zeroing)
        #expect(ref.qualifier == .zeroing)
        #expect(ref.role == .governing)
        #expect(ref.element == .s)
    }

    @Test func mergingGoverningPredicateCarriesItsQualifier() {
        let ref = ScalablePredicateRef(registerIndex: 4, element: .d, qualifier: .merging)
        #expect(ref.qualifier == .merging)
        #expect(ref.role == .governing)
    }

    @Test func resultPredicateIsDistinctFromAGoverningOne() {
        let governing = ScalablePredicateRef(registerIndex: 1, element: .s,
                                             qualifier: .zeroing, role: .governing)
        let result = ScalablePredicateRef(registerIndex: 2, element: .s, role: .result)
        #expect(governing.role == .governing)
        #expect(result.role == .result)
        #expect(result.qualifier == .none)
        #expect(governing != result)
    }

    @Test func counterViewSelectsThePredicateAsCounterForm() {
        let counter = ScalablePredicateRef(registerIndex: 8, isCounter: true)
        #expect(counter.isCounter)
        #expect(counter.registerIndex == 8)
    }

    @Test func counterAndMaskViewsOfOneRegisterAreDistinctOperandsOnTheSameRegister() {
        let counter = ScalablePredicateRef(registerIndex: 8, isCounter: true)
        let mask = ScalablePredicateRef(registerIndex: 8, isCounter: false)
        #expect(counter != mask)
        #expect(counter.registerIndex == mask.registerIndex)
    }

    @Test func elementIndexCarriesTheImmediateOnIndexedForms() {
        let ref = ScalablePredicateRef(registerIndex: 8, isCounter: true, elementIndex: 1)
        #expect(ref.elementIndex == 1)
    }

    @Test func sizedAndBarePredicatesAreDistinct() {
        let sized = ScalablePredicateRef(registerIndex: 3, element: .b)
        let bare = ScalablePredicateRef(registerIndex: 3)
        #expect(sized != bare)
        #expect(sized.element == .b)
        #expect(bare.element == nil)
    }

    @Test func roleRawValuesAreStable() {
        #expect(ScalablePredicateRef.Role.governing.rawValue == 0)
        #expect(ScalablePredicateRef.Role.result.rawValue == 1)
        #expect(ScalablePredicateRef.Role(rawValue: 0) == .governing)
        #expect(ScalablePredicateRef.Role(rawValue: 1) == .result)
        #expect(ScalablePredicateRef.Role(rawValue: 2) == nil)
    }

    @Test func equalRefsHashEqual() {
        let a = ScalablePredicateRef(registerIndex: 5, element: .h, qualifier: .merging)
        let b = ScalablePredicateRef(registerIndex: 5, element: .h, qualifier: .merging)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates `PredicateQualifier`, the `/Z` versus `/M` distinction.
@Suite("PredicateQualifier / zeroing vs merging")
struct PredicateQualifierTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(PredicateQualifier.none.rawValue == 0)
        #expect(PredicateQualifier.zeroing.rawValue == 1)
        #expect(PredicateQualifier.merging.rawValue == 2)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 2 {
            #expect(PredicateQualifier(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeRawValueReturnsNil() {
        #expect(PredicateQualifier(rawValue: 3) == nil)
    }

    @Test func theThreeQualifiersAreDistinct() {
        let all: Set<PredicateQualifier> = [.none, .zeroing, .merging]
        #expect(all.count == 3)
    }
}

/// Validates `SVEPredicatePattern`, the 5-bit constraint operand on PTRUE and
/// the element-count instructions, plus the `mul #k` multiplier riding.
@Suite("SVEPredicatePattern / raw pattern field and multiplier")
struct SVEPredicatePatternTests {
    @Test func rawFieldIsMaskedToFiveBits() {
        #expect(SVEPredicatePattern(raw: 0xFF).raw == 31)
        #expect(SVEPredicatePattern(raw: 32).raw == 0)
    }

    @Test func everyPatternEncodingRoundTrips() {
        for raw: UInt8 in 0 ... 31 {
            #expect(SVEPredicatePattern(raw: raw).raw == raw)
        }
    }

    @Test func multiplierDefaultsToOneWhenAbsent() {
        #expect(SVEPredicatePattern(raw: 31).multiplier == 1)
    }

    @Test func multiplierCarriesTheMulFactor() {
        let pattern = SVEPredicatePattern(raw: 0b11111, multiplier: 4)
        #expect(pattern.raw == 31)
        #expect(pattern.multiplier == 4)
    }

    @Test func patternsDifferingOnlyInMultiplierAreDistinct() {
        #expect(SVEPredicatePattern(raw: 31) != SVEPredicatePattern(raw: 31, multiplier: 2))
    }

    @Test func equalPatternsHashEqual() {
        let a = SVEPredicatePattern(raw: 5, multiplier: 3)
        let b = SVEPredicatePattern(raw: 5, multiplier: 3)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

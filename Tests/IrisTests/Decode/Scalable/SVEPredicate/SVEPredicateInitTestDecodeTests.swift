// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func predicates(_ set: ScalableRegisterSet) -> [UInt8] {
    (0 ..< 16).filter { set.containsPredicate(UInt8($0)) }.map(UInt8.init)
}

/// Validates the predicate initialise-and-test group.
@Suite("SVE predicate & control / initialise and test")
struct SVEPredicateInitTestDecodeTests {
    @Test func ptrueCarriesItsSizeAndPatternAndWritesOnlyItsDestination() {
        let d = decode(0x2518_E000)
        #expect(d.mnemonic == .ptrue)
        #expect(d.category == .sve)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0, element: .b, role: .result)),
            .svePredicatePattern(SVEPredicatePattern(raw: 0)),
        ])
        #expect(predicates(d.scalableWrites) == [0])
        #expect(d.scalableReads == .empty)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == .empty)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func ptrueDecodesEveryElementSize() {
        let cases: [(UInt32, ScalarSize, UInt8, UInt8)] = [
            (0x2518_E000, .b, 0, 0),
            (0x2558_E105, .h, 8, 5),
            (0x2598_E1E9, .s, 15, 9),
            (0x25D8_E3EF, .d, 31, 15),
        ]
        for (encoding, size, pattern, destination) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == .ptrue)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: destination, element: size, role: .result)),
                .svePredicatePattern(SVEPredicatePattern(raw: pattern)),
            ])
            #expect(predicates(d.scalableWrites) == [destination])
        }
    }

    @Test func ptruesIsTheFlagSettingForm() {
        for encoding: UInt32 in [0x2599_E3C3, 0x2519_E3E0] {
            let d = decode(encoding)
            #expect(d.mnemonic == .ptrues)
            #expect(d.flagEffect == .nzcv)
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func ptrueRejectsItsReservedBits() {
        #expect(decode(0x251A_E000).mnemonic == .undefined)
        #expect(decode(0x2518_E010).mnemonic == .undefined)
    }

    @Test func pfalseWritesAnAllFalseByteElementPredicate() {
        let d = decode(0x2518_E407)
        #expect(d.mnemonic == .pfalse)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 7, element: .b, role: .result)),
        ])
        #expect(predicates(d.scalableWrites) == [7])
        #expect(d.scalableReads == .empty)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func pfalseRejectsEveryReservedField() {
        #expect(decode(0x2558_E400).mnemonic == .undefined)
        #expect(decode(0x2519_E400).mnemonic == .undefined)
        #expect(decode(0x2518_E600).mnemonic == .undefined)
        #expect(decode(0x2518_E410).mnemonic == .undefined)
    }

    @Test func ptestReadsBothPredicatesAndWritesOnlyTheFlags() {
        let d = decode(0x2550_C440)
        #expect(d.mnemonic == .ptest)
        #expect(d.flagEffect == .nzcv)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [1, 2])
        #expect(d.scalableWrites == .empty)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func ptestReachesTheHighestPredicateRegisters() {
        let d = decode(0x2550_FDC0)
        #expect(predicates(d.scalableReads) == [14, 15])
    }

    @Test func ptestRejectsItsReservedBits() {
        #expect(decode(0x2510_C000).mnemonic == .undefined)
        #expect(decode(0x2551_C000).mnemonic == .undefined)
        #expect(decode(0x2550_C200).mnemonic == .undefined)
        #expect(decode(0x2550_C001).mnemonic == .undefined)
    }
}

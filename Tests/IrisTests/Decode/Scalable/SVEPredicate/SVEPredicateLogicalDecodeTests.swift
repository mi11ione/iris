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

/// Validates the predicate-logical group.
@Suite("SVE predicate & control / predicate logical")
struct SVEPredicateLogicalDecodeTests {
    private static let allocated: [(UInt32, Mnemonic, Bool)] = [
        (0x2503_4820, .and, false),
        (0x2503_4830, .bic, false),
        (0x2503_4A20, .eor, false),
        (0x2503_4A30, .sel, false),
        (0x2543_4820, .ands, true),
        (0x2543_4830, .bics, true),
        (0x2543_4A20, .eors, true),
        (0x2583_4820, .orr, false),
        (0x2583_4830, .orn, false),
        (0x2583_4A20, .nor, false),
        (0x2583_4A30, .nand, false),
        (0x25C3_4820, .orrs, true),
        (0x25C3_4830, .orns, true),
        (0x25C3_4A20, .nors, true),
        (0x25C3_4A30, .nands, true),
    ]

    @Test func everyAllocatedOpcodeDecodesToItsMnemonic() {
        for (encoding, mnemonic, setsFlags) in Self.allocated {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == (setsFlags ? .nzcv : .none), "\(mnemonic.rawValue)")
            #expect(d.category == .sve)
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func everyAllocatedOpcodeReadsThreePredicatesAndWritesOne() {
        for (encoding, mnemonic, _) in Self.allocated {
            let d = decode(encoding)
            #expect(predicates(d.scalableReads) == [1, 2, 3], "\(mnemonic.rawValue)")
            #expect(predicates(d.scalableWrites) == [0], "\(mnemonic.rawValue)")
            #expect(d.semanticReads == .empty)
            #expect(d.semanticWrites == .empty)
        }
    }

    @Test func theGoverningPredicateZeroesOnEveryFormExceptSelect() {
        for (encoding, mnemonic, _) in Self.allocated {
            let d = decode(encoding)
            let expectedGoverning = mnemonic == .sel
                ? ScalablePredicateRef(registerIndex: 2, role: .governing)
                : ScalablePredicateRef(registerIndex: 2, qualifier: .zeroing, role: .governing)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 0, element: .b, role: .result)),
                .scalablePredicate(expectedGoverning),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 1, element: .b)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b)),
            ], "\(mnemonic.rawValue)")
        }
    }

    @Test func theSelectWithFlagsSlotIsAnArchitecturalHole() {
        let d = decode(0x2543_4A30)
        #expect(d.mnemonic == .undefined)
        #expect(d.category == .sve)
        #expect(d.operands.isEmpty)
    }

    @Test func orrOfOneRegisterWithItselfIsTheTwoOperandMove() {
        let d = decode(0x2584_5081)
        #expect(d.mnemonic == .mov)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 4, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [4])
        #expect(predicates(d.scalableWrites) == [1])
    }

    @Test func theFlagSettingTwoOperandMoveComesFromOrrs() {
        let d = decode(0x25C4_5081)
        #expect(d.mnemonic == .movs)
        #expect(d.flagEffect == .nzcv)
        #expect(d.operands.count == 2)
    }

    @Test func andWithEqualSourcesIsTheZeroingMove() {
        let d = decode(0x2506_48C1)
        #expect(d.mnemonic == .mov)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, qualifier: .zeroing, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 6, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [2, 6])
        #expect(predicates(d.scalableWrites) == [1])
    }

    @Test func theFlagSettingZeroingMoveComesFromAnds() {
        let d = decode(0x2546_48C1)
        #expect(d.mnemonic == .movs)
        #expect(d.flagEffect == .nzcv)
        #expect(d.operands.count == 3)
    }

    @Test func selectIntoItsOwnSecondSourceIsTheMergingMove() {
        let d = decode(0x2505_4A75)
        #expect(d.mnemonic == .mov)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 5, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, qualifier: .merging, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [2, 3, 5], "the destination is read as the select source")
        #expect(predicates(d.scalableWrites) == [5])
        #expect(d.scalableEffect == .readsStreamingMode)
        #expect(!d.scalableEffect.contains(.partialWrite))
    }

    @Test func exclusiveOrAgainstItsGoverningPredicateIsTheNot() {
        let d = decode(0x2507_5E41)
        #expect(d.mnemonic == .not)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 7, qualifier: .zeroing, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [2, 7])
        #expect(predicates(d.scalableWrites) == [1])
    }

    @Test func theFlagSettingNotComesFromEors() {
        let d = decode(0x2547_5E41)
        #expect(d.mnemonic == .nots)
        #expect(d.flagEffect == .nzcv)
        #expect(d.operands.count == 3)
    }

    @Test func anAliasNeedsItsExactRegisterEquality() {
        let nearMisses: [(UInt32, Mnemonic)] = [
            (0x2584_50A1, .orr),
            (0x2506_48A1, .and),
            (0x2505_4A76, .sel),
            (0x2507_5A41, .eor),
        ]
        for (encoding, mnemonic) in nearMisses {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.operands.count == 4)
        }
    }

    @Test func theNonAliasingOpcodesNeverAliasHoweverTheirRegistersLineUp() {
        let registerFields: UInt32 = 0x000F_3DEF
        for (base, mnemonic, _) in Self.allocated {
            guard mnemonic == .bic || mnemonic == .bics || mnemonic == .orn || mnemonic == .orns
                || mnemonic == .nor || mnemonic == .nors || mnemonic == .nand || mnemonic == .nands
            else { continue }
            let allSame = base & ~registerFields
            let d = decode(allSame)
            #expect(d.mnemonic == mnemonic, "0x\(String(allSame, radix: 16)) aliased when it must not")
            #expect(d.operands.count == 4)
        }
    }
}

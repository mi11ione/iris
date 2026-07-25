// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0, features: .scalable)
}

private func predicates(_ set: ScalableRegisterSet) -> [UInt8] {
    (0 ..< 16).filter { set.containsPredicate(UInt8($0)) }.map(UInt8.init)
}

/// Validates the loop-predicate group — the eight WHILE conditions, the two
/// memory-hazard WHILEs, and CTERM. These are the instructions that turn a
/// scalar loop bound into a lane mask, and they are the most common SVE
/// instructions Apple actually ships. CTERM is the exception in every
/// dimension: it writes no register, it writes only two of the four condition
/// flags while *reading* a third, and it is the only form in the group whose
/// result does not depend on the vector length — so it must not carry the
/// streaming-mode effect the rest of the tier does.
@Suite("SVE predicate & control / loop predicates")
struct SVELoopPredicateDecodeTests {
    /// The eight conditions, in `{unsigned, less-than, equal}` opcode order,
    /// with a 32-bit and a 64-bit operand form each.
    private static let conditions: [(word32: UInt32, word64: UInt32, mnemonic: Mnemonic)] = [
        (0x2525_00C7, 0x25E5_10C7, .whilege),
        (0x2525_00D7, 0x25E5_10D7, .whilegt),
        (0x2525_04C7, 0x25E5_14C7, .whilelt),
        (0x2525_04D7, 0x25E5_14D7, .whilele),
        (0x2525_08C7, 0x25E5_18C7, .whilehs),
        (0x2525_08D7, 0x25E5_18D7, .whilehi),
        (0x2525_0CC7, 0x25E5_1CC7, .whilelo),
        (0x2525_0CD7, 0x25E5_1CD7, .whilels),
    ]

    @Test func everyConditionDecodesInItsThirtyTwoBitForm() {
        for (word32, _, mnemonic) in Self.conditions {
            let d = decode(word32)
            #expect(d.mnemonic == mnemonic, "0x\(String(word32, radix: 16))")
            #expect(d.flagEffect == .nzcv)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 7, element: .b, role: .result)),
                .register(.w(6)),
                .register(.w(5)),
            ])
            #expect(d.semanticReads == RegisterSet.empty.inserting(.w(6)).inserting(.w(5)))
            #expect(d.semanticWrites == .empty)
            #expect(predicates(d.scalableWrites) == [7])
            #expect(d.scalableReads == .empty, "no governing predicate")
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func everyConditionDecodesInItsSixtyFourBitForm() {
        for (_, word64, mnemonic) in Self.conditions {
            let d = decode(word64)
            #expect(d.mnemonic == mnemonic, "0x\(String(word64, radix: 16))")
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 7, element: .d, role: .result)),
                .register(.x(6)),
                .register(.x(5)),
            ])
            #expect(d.semanticReads == RegisterSet.empty.inserting(.x(6)).inserting(.x(5)))
        }
    }

    @Test func theLoopPredicateTakesEverySize() {
        for (encoding, size) in [(UInt32(0x2525_04C7), ScalarSize.b), (0x25A5_04C7, .s)] {
            let d = decode(encoding)
            #expect(d.mnemonic == .whilelt)
            #expect(d.operands[0]
                == .scalablePredicate(ScalablePredicateRef(registerIndex: 7, element: size, role: .result)))
        }
    }

    @Test func theLoopPredicateOverTheZeroRegisterKeepsNoDependency() {
        let d = decode(0x257F_17E0) // whilelt p0.h, xzr, xzr
        #expect(d.mnemonic == .whilelt)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 0, element: .h, role: .result)),
            .register(.xzr()),
            .register(.xzr()),
        ])
        #expect(d.semanticReads == .empty)
        #expect(predicates(d.scalableWrites) == [0])
    }

    @Test func theMemoryHazardLoopPredicatesTakeSixtyFourBitOperandsOnly() {
        for (encoding, mnemonic, size) in [
            (UInt32(0x2525_30C7), Mnemonic.whilewr, ScalarSize.b),
            (0x25E5_30D7, .whilerw, .d),
        ] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == .nzcv)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 7, element: size, role: .result)),
                .register(.x(6)),
                .register(.x(5)),
            ], "the hazard forms are address-typed — always 64-bit")
            #expect(d.semanticReads == RegisterSet.empty.inserting(.x(6)).inserting(.x(5)))
            #expect(predicates(d.scalableWrites) == [7])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func conditionalTerminateWritesNoRegisterAndOnlyTwoFlags() {
        let d = decode(0x25A5_20C0) // ctermeq w6, w5
        #expect(d.mnemonic == .ctermeq)
        #expect(Array(d.operands) == [.register(.w(6)), .register(.w(5))])
        #expect(d.semanticReads == RegisterSet.empty.inserting(.w(6)).inserting(.w(5)))
        #expect(d.semanticWrites == .empty)
        #expect(d.scalableReads == .empty)
        #expect(d.scalableWrites == .empty)
        #expect(
            d.flagEffect == [.writesN, .writesV, .readsC],
            "it writes N and V, preserves Z, and reads C — not a plain NZCV write",
        )
        #expect(
            d.scalableEffect == .none,
            "a scalar compare has no vector length, so no streaming-mode dependence",
        )
    }

    @Test func conditionalTerminateHasBothConditionsAndBothWidths() {
        let d = decode(0x25E5_20D0) // ctermne x6, x5
        #expect(d.mnemonic == .ctermne)
        #expect(Array(d.operands) == [.register(.x(6)), .register(.x(5))])
        #expect(d.flagEffect == [.writesN, .writesV, .readsC])
    }

    @Test func conditionalTerminateOverTheZeroRegisterKeepsNoDependency() {
        let d = decode(0x25FF_23E0) // ctermeq xzr, xzr
        #expect(d.mnemonic == .ctermeq)
        #expect(Array(d.operands) == [.register(.xzr()), .register(.xzr())])
        #expect(d.semanticReads == .empty)
    }

    @Test func conditionalTerminateRejectsItsReservedDestinationField() {
        // CTERM has no destination; the four bits where one would sit are zero.
        #expect(decode(0x25E5_20C1).mnemonic == .undefined)
    }

    @Test func theUnallocatedLoopPredicateOpcodesBelongToNoDecoder() {
        // Two encodings in this neighbourhood look like loop predicates but are
        // not allocated: the hazard-form opcode with a wrong middle field, and
        // CTERM with its high opcode bit clear. Neither is claimed, and the
        // family decoder still produces a well-formed UNDEFINED for them.
        for encoding: UInt32 in [0x2525_28C7, 0x2565_20C0] {
            let d = decode(encoding)
            #expect(d.mnemonic == .undefined)
            #expect(d.category == .sve)
        }
    }
}

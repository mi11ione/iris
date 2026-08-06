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

/// Validates INDEX, the vector-of-stepped-values generator.
@Suite("SVE predicate & control / index generation")
struct SVEIndexDecodeTests {
    @Test func bothOperandsCanBeImmediates() {
        let d = decode(0x0423_4020)
        #expect(d.mnemonic == .index)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .b)),
            .immediate(value: 1, width: 5),
            .immediate(value: 3, width: 5),
        ])
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 0)))
        #expect(d.scalableReads == .empty)
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func bothImmediatesAreSignExtendedFromFiveBits() {
        let d = decode(0x04FF_4200)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .d)),
            .immediate(value: -16, width: 5),
            .immediate(value: -1, width: 5),
        ])
    }

    @Test func theStartOperandCanBeARegisterOnItsOwn() {
        let d = decode(0x0462_44A1)
        #expect(d.mnemonic == .index)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 1, element: .h)),
            .register(.w(5)),
            .immediate(value: 2, width: 5),
        ])
        #expect(d.semanticReads == RegisterSet.empty.inserting(.w(5)))
    }

    @Test func theStepOperandCanBeARegisterOnItsOwn() {
        let d = decode(0x04A6_4842)
        #expect(d.mnemonic == .index)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 2, element: .s)),
            .immediate(value: 2, width: 5),
            .register(.w(6)),
        ])
        #expect(d.semanticReads == RegisterSet.empty.inserting(.w(6)))
    }

    @Test func bothOperandsCanBeRegistersAndTheDoublewordFormIsSixtyFourBit() {
        let d = decode(0x04E6_4CA3)
        #expect(d.mnemonic == .index)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 3, element: .d)),
            .register(.x(5)),
            .register(.x(6)),
        ], "the doubleword element size widens both register operands")
        #expect(d.semanticReads == RegisterSet.empty.inserting(.x(5)).inserting(.x(6)))
        #expect(d.semanticWrites == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 3)))
    }

    @Test func registerThirtyOneIsTheZeroRegisterNotTheStackPointer() {
        let d = decode(0x043F_4FE4)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 4, element: .b)),
            .register(.wzr()),
            .register(.wzr()),
        ])
        #expect(d.semanticReads == .empty)
    }
}

/// Validates MOVPRFX in its unpredicated and predicated forms.
@Suite("SVE predicate & control / constructive prefix")
struct SVEMovprfxDecodeTests {
    @Test func theUnpredicatedPrefixCopiesAWholeVector() {
        let d = decode(0x0420_BC20)
        #expect(d.mnemonic == .movprfx)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0)),
            .scalableVector(ScalableVectorRef(registerIndex: 1)),
        ], "the unpredicated form carries no element size")
        #expect(d.semanticReads == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 1)))
        #expect(d.semanticWrites == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 0)))
        #expect(d.scalableReads == .empty)
        #expect(d.scalableEffect == .readsStreamingMode)
        #expect(!d.scalableEffect.contains(.partialWrite))
    }

    @Test func theUnpredicatedPrefixRejectsItsReservedFields() {
        #expect(decode(0x0460_BC20).mnemonic == .undefined)
        #expect(decode(0x0421_BC20).mnemonic == .undefined)
    }

    @Test func theZeroingPredicatedPrefixFullyWritesItsDestination() {
        let d = decode(0x0450_2C20)
        #expect(d.mnemonic == .movprfx)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .h)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, qualifier: .zeroing, role: .governing)),
            .scalableVector(ScalableVectorRef(registerIndex: 1, element: .h)),
        ])
        #expect(predicates(d.scalableReads) == [3])
        #expect(d.semanticReads == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 1)))
        #expect(d.semanticWrites == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 0)))
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theMergingPredicatedPrefixReadsItsDestinationAndWritesItPartially() {
        let d = decode(0x0491_3C20)
        #expect(d.mnemonic == .movprfx)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0, element: .s)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 7, qualifier: .merging, role: .governing)),
            .scalableVector(ScalableVectorRef(registerIndex: 1, element: .s)),
        ])
        #expect(predicates(d.scalableReads) == [7])
        #expect(
            d.semanticReads == RegisterSet.empty
                .inserting(ScalableVectorRef(registerIndex: 0))
                .inserting(ScalableVectorRef(registerIndex: 1)),
            "the merging form reads its destination",
        )
        #expect(d.semanticWrites == RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 0)))
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func thePredicatedPrefixTakesEverySize() {
        let cases: [(UInt32, ScalarSize)] = [
            (0x0410_2C20, .b), (0x0450_2C20, .h), (0x0490_2C20, .s), (0x04D0_2C20, .d),
        ]
        for (encoding, size) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == .movprfx, "0x\(String(encoding, radix: 16))")
            #expect(d.operands[0] == .scalableVector(ScalableVectorRef(registerIndex: 0, element: size)))
            #expect(d.operands[2] == .scalableVector(ScalableVectorRef(registerIndex: 1, element: size)))
        }
    }

    @Test func thePredicatedPrefixTakesOnlyTheLowEightPredicates() {
        let withoutPredicate = UInt32(0x0450_2C20) & ~0x1C00
        for register in UInt8(0) ... 7 {
            let d = decode(withoutPredicate | (UInt32(register) << 10))
            #expect(d.mnemonic == .movprfx)
            #expect(predicates(d.scalableReads) == [register])
            #expect(d.operands[1]
                == .scalablePredicate(ScalablePredicateRef(
                    registerIndex: register, qualifier: .zeroing, role: .governing,
                )))
        }
    }

    @Test func aPrefixCopyingAVectorOntoItselfIsNotRejected() {
        let d = decode(0x0420_BC00)
        #expect(d.mnemonic == .movprfx)
        #expect(Array(d.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 0)),
            .scalableVector(ScalableVectorRef(registerIndex: 0)),
        ])
    }
}

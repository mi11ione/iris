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

/// Validates the predicate-count group — CNTP and the six accumulate forms
/// (INCP/DECP plus their four saturating variants) in both their scalar and
/// vector shapes. The load-bearing distinction is the role of the predicate:
/// CNTP's is a real governing predicate (it gates which lanes are counted),
/// while every accumulate form's predicate is a plain data source — it gates
/// nothing, it *is* the value being counted. Getting that backwards would make
/// the accumulate forms look conditionally executed to a dataflow consumer.
@Suite("SVE predicate & control / predicate count")
struct SVEPredicateCountDecodeTests {
    @Test func countActiveLanesGovernsWithOnePredicateAndCountsAnother() {
        let d = decode(0x2520_8443) // cntp x3, p1, p2.b
        #expect(d.mnemonic == .cntp)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .register(.x(3)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ], "the governing predicate is bare; the counted one carries its size")
        #expect(predicates(d.scalableReads) == [1, 2])
        #expect(d.scalableWrites == .empty)
        #expect(d.semanticWrites == RegisterSet.empty.inserting(.x(3)))
        #expect(d.semanticReads == .empty, "the destination is overwritten, not accumulated")
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func countActiveLanesTakesEverySize() {
        let cases: [(UInt32, ScalarSize)] = [
            (0x2520_8443, .b), (0x2560_8443, .h), (0x25A0_8443, .s), (0x25E0_8443, .d),
        ]
        for (encoding, size) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == .cntp)
            #expect(d.operands[2] == .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: size)))
        }
    }

    @Test func countActiveLanesIntoTheZeroRegisterKeepsNoWrite() {
        let d = decode(0x25E0_845F) // cntp xzr, p1, p2.d
        #expect(d.mnemonic == .cntp)
        #expect(d.operands[0] == .register(.xzr()))
        #expect(d.semanticWrites == .empty, "a write to the zero register is not a dependency")
    }

    @Test func theVectorAccumulateFormsReadAndWriteTheSameVector() {
        let cases: [(UInt32, Mnemonic)] = [
            (0x2568_8043, .sqincp),
            (0x2569_8043, .uqincp),
            (0x256A_8043, .sqdecp),
            (0x256B_8043, .uqdecp),
            (0x256C_8043, .incp),
            (0x256D_8043, .decp),
        ]
        for (encoding, mnemonic) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == .none, "saturation is silent — no flags")
            #expect(Array(d.operands) == [
                .scalableVector(ScalableVectorRef(registerIndex: 3, element: .h)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .h)),
            ], "the predicate is a sized data source, not a bare governing predicate")
            #expect(predicates(d.scalableReads) == [2])
            #expect(d.scalableWrites == .empty)
            let vector = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 3))
            #expect(d.semanticReads == vector)
            #expect(d.semanticWrites == vector)
            #expect(d.scalableEffect == .readsStreamingMode, "every lane is recomputed — a full write")
        }
    }

    @Test func theVectorAccumulateFormsTakeEverySizeExceptByte() {
        for (encoding, size) in [(UInt32(0x25AC_8043), ScalarSize.s), (0x25EC_8043, .d)] {
            let d = decode(encoding)
            #expect(d.mnemonic == .incp)
            #expect(d.operands[0] == .scalableVector(ScalableVectorRef(registerIndex: 3, element: size)))
        }
        // There is no byte-element vector accumulate.
        #expect(decode(0x252C_8043).mnemonic == .undefined)
    }

    @Test func theVectorAccumulateFormsRejectTheScalarWidthBit() {
        // Bit 10 selects the 32/64-bit view of a *scalar* destination; on the
        // vector form it is a fixed zero.
        #expect(decode(0x256C_8443).mnemonic == .undefined)
    }

    @Test func theVectorAccumulateReachesTheHighestVectorRegister() {
        let d = decode(0x25EC_805F) // incp z31.d, p2.d
        #expect(d.mnemonic == .incp)
        #expect(d.operands[0] == .scalableVector(ScalableVectorRef(registerIndex: 31, element: .d)))
        let z31 = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 31))
        #expect(d.semanticWrites == z31)
    }

    @Test func theScalarAccumulateFormsReadAndWriteTheSameRegister() {
        for (encoding, mnemonic) in [(UInt32(0x256C_8843), Mnemonic.incp), (0x25ED_8843, .decp)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(d.operands.count == 2)
            #expect(d.operands[0] == .register(.x(3)))
            let x3 = RegisterSet.empty.inserting(.x(3))
            #expect(d.semanticReads == x3)
            #expect(d.semanticWrites == x3)
            #expect(predicates(d.scalableReads) == [2])
        }
    }

    @Test func theScalarAccumulateFormsRejectTheSaturatingWidthBit() {
        // The non-saturating scalar forms are 64-bit only; bit 10 is reserved.
        #expect(decode(0x256C_8C43).mnemonic == .undefined)
    }

    @Test func theScalarAccumulateIntoTheZeroRegisterKeepsNoDependency() {
        let d = decode(0x256C_885F) // incp xzr, p2.h
        #expect(d.mnemonic == .incp)
        #expect(d.operands[0] == .register(.xzr()))
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == .empty)
    }

    @Test func theSignedSaturatingScalarPrintsATrailingThirtyTwoBitView() {
        // The signed 32-bit saturating form has one register field but two
        // views of it: a 64-bit destination and a 32-bit source.
        for (encoding, mnemonic) in [(UInt32(0x2568_8843), Mnemonic.sqincp), (0x256A_8843, .sqdecp)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(Array(d.operands) == [
                .register(.x(3)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .h)),
                .register(.w(3)),
            ])
            let x3 = RegisterSet.empty.inserting(.x(3))
            #expect(d.semanticReads == x3, "both views are the same physical register")
            #expect(d.semanticWrites == x3)
        }
    }

    @Test func theUnsignedSaturatingScalarNarrowsItsDestinationInstead() {
        for (encoding, mnemonic) in [(UInt32(0x2569_8843), Mnemonic.uqincp), (0x256B_8843, .uqdecp)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(Array(d.operands) == [
                .register(.w(3)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .h)),
            ], "the unsigned 32-bit form has no trailing source view")
        }
    }

    @Test func theSixtyFourBitSaturatingScalarsTakeASingleRegister() {
        let cases: [(UInt32, Mnemonic)] = [
            (0x2568_8C43, .sqincp),
            (0x2569_8C43, .uqincp),
            (0x256A_8C43, .sqdecp),
            (0x256B_8C43, .uqdecp),
        ]
        for (encoding, mnemonic) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(Array(d.operands) == [
                .register(.x(3)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .h)),
            ])
        }
    }

    @Test func theSignedSaturatingScalarIntoTheZeroRegisterKeepsNoDependency() {
        let d = decode(0x2568_885F) // sqincp xzr, p2.h, wzr
        #expect(d.mnemonic == .sqincp)
        #expect(Array(d.operands) == [
            .register(.xzr()),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .h)),
            .register(.wzr()),
        ])
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == .empty)
    }

    @Test func theAccumulateOpcodeRejectsItsUnallocatedValues() {
        #expect(decode(0x256E_8043).mnemonic == .undefined) // op 110, vector
        #expect(decode(0x256F_8843).mnemonic == .undefined) // op 111, scalar
        #expect(decode(0x256C_8243).mnemonic == .undefined) // bit 9 reserved
    }
}

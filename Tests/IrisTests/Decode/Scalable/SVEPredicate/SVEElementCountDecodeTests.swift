// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates the element-count group.
@Suite("SVE predicate & control / element count")
struct SVEElementCountDecodeTests {
    @Test func thePlainCountsWriteTheirDestinationWithoutReadingIt() {
        let cases: [(UInt32, Mnemonic)] = [
            (0x0420_E3E0, .cntb), (0x0460_E101, .cnth), (0x04A1_E3E2, .cntw), (0x04EF_E003, .cntd),
        ]
        for (encoding, mnemonic) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == .none)
            #expect(d.semanticReads == .empty, "a plain count is not an accumulate")
            #expect(d.scalableReads == .empty)
            #expect(d.scalableWrites == .empty)
            #expect(d.scalableEffect == .readsStreamingMode)
            #expect(d.operands.count == 2)
        }
    }

    @Test func theCountCarriesItsPatternAndMultiplier() {
        let d = decode(0x04EF_E003)
        #expect(Array(d.operands) == [
            .register(.x(3)),
            .svePredicatePattern(SVEPredicatePattern(raw: 0, multiplier: 16)),
        ])
        #expect(d.semanticWrites == RegisterSet.empty.inserting(.x(3)))

        let noMultiplier = decode(0x0460_E101)
        #expect(noMultiplier.operands[1] == .svePredicatePattern(SVEPredicatePattern(raw: 8, multiplier: 1)))
    }

    @Test func theCountRejectsItsReservedBits() {
        #expect(decode(0x0420_E7E0).mnemonic == .undefined)
        #expect(decode(0x0420_EBE0).mnemonic == .undefined)
    }

    @Test func theScalarIncrementsAndDecrementsAccumulate() {
        let cases: [(UInt32, Mnemonic, UInt8)] = [
            (0x0430_E3E4, .incb, 4), (0x0470_E085, .inch, 5), (0x04B2_E3C6, .incw, 6), (0x04F0_E3E7, .incd, 7),
            (0x0430_E7E8, .decb, 8), (0x0470_E7E9, .dech, 9), (0x04B0_E7EA, .decw, 10), (0x04F0_E7FF, .decd, 31),
        ]
        for (encoding, mnemonic, register) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            let mask = register == 31 ? RegisterSet.empty : RegisterSet.empty.inserting(.x(register))
            #expect(d.semanticReads == mask, "the destination is also a source")
            #expect(d.semanticWrites == mask)
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func theSignedSaturatingScalarKeepsASixtyFourBitDestinationAndAThirtyTwoBitSource() {
        for (encoding, mnemonic) in [(UInt32(0x0420_F3E1), Mnemonic.sqincb), (0x0420_FBE1, .sqdecb)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(Array(d.operands) == [
                .register(.x(1)),
                .register(.w(1)),
                .svePredicatePattern(SVEPredicatePattern(raw: 31, multiplier: 1)),
            ])
            let x1 = RegisterSet.empty.inserting(.x(1))
            #expect(d.semanticReads == x1, "both views are the same physical register")
            #expect(d.semanticWrites == x1)
        }
    }

    @Test func theUnsignedSaturatingScalarNarrowsItsDestination() {
        for (encoding, mnemonic) in [(UInt32(0x0420_F7E1), Mnemonic.uqincb), (0x0420_FFE1, .uqdecb)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(Array(d.operands) == [
                .register(.w(1)),
                .svePredicatePattern(SVEPredicatePattern(raw: 31, multiplier: 1)),
            ], "the unsigned 32-bit form has no trailing source view")
        }
    }

    @Test func theSixtyFourBitSaturatingScalarsTakeASingleRegister() {
        let cases: [(UInt32, Mnemonic)] = [
            (0x04F0_F3E1, .sqincd), (0x04F0_F7E1, .uqincd), (0x04F0_FBE1, .sqdecd), (0x04F0_FFE1, .uqdecd),
        ]
        for (encoding, mnemonic) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(Array(d.operands) == [
                .register(.x(1)),
                .svePredicatePattern(SVEPredicatePattern(raw: 31, multiplier: 1)),
            ])
        }
    }

    @Test func theSaturatingScalarsCarryTheirPatternAndMultiplierAfterEveryRegister() {
        let signed = decode(0x0421_F3E0)
        #expect(Array(signed.operands) == [
            .register(.x(0)),
            .register(.w(0)),
            .svePredicatePattern(SVEPredicatePattern(raw: 31, multiplier: 2)),
        ])

        let unsigned = decode(0x0460_F440)
        #expect(unsigned.mnemonic == .uqinch)
        #expect(Array(unsigned.operands) == [
            .register(.w(0)),
            .svePredicatePattern(SVEPredicatePattern(raw: 2, multiplier: 1)),
        ])

        let wide = decode(0x04B3_FBC0)
        #expect(wide.mnemonic == .sqdecw)
        #expect(Array(wide.operands) == [
            .register(.x(0)),
            .svePredicatePattern(SVEPredicatePattern(raw: 30, multiplier: 4)),
        ])
    }

    @Test func theSaturatingScalarsIntoTheZeroRegisterKeepNoDependency() {
        let unsigned = decode(0x04E0_FFFF)
        #expect(unsigned.operands[0] == .register(.wzr()))
        #expect(unsigned.semanticReads == .empty)
        #expect(unsigned.semanticWrites == .empty)

        let signed = decode(0x04E0_F3FF)
        #expect(signed.operands[0] == .register(.xzr()))
        #expect(signed.operands[1] == .register(.wzr()))
        #expect(signed.semanticReads == .empty)
    }

    @Test func theVectorCountsAccumulateIntoTheirVectorDestination() {
        let cases: [(UInt32, Mnemonic)] = [
            (0x0460_C3E2, .sqinch), (0x0460_C7E2, .uqinch), (0x0460_CBE2, .sqdech), (0x0460_CFE2, .uqdech),
            (0x0470_C3E2, .inch),
        ]
        for (encoding, mnemonic) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(Array(d.operands) == [
                .scalableVector(ScalableVectorRef(registerIndex: 2, element: .h)),
                .svePredicatePattern(SVEPredicatePattern(raw: 31, multiplier: 1)),
            ])
            let z2 = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 2))
            #expect(d.semanticReads == z2)
            #expect(d.semanticWrites == z2)
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func theVectorCountsTakeEverySizeExceptByte() {
        let d = decode(0x04F0_C7E2)
        #expect(d.mnemonic == .decd)
        #expect(d.operands[0] == .scalableVector(ScalableVectorRef(registerIndex: 2, element: .d)))

        let multiplied = decode(0x04B3_C3A2)
        #expect(multiplied.mnemonic == .incw)
        #expect(Array(multiplied.operands) == [
            .scalableVector(ScalableVectorRef(registerIndex: 2, element: .s)),
            .svePredicatePattern(SVEPredicatePattern(raw: 29, multiplier: 4)),
        ])

        #expect(decode(0x0430_C3E2).mnemonic == .undefined, "there is no byte-element vector count")
    }

    @Test func theNonSaturatingVectorCountHasNoDecrementOpcodeAboveOne() {
        #expect(decode(0x0470_CBE2).mnemonic == .undefined)
        #expect(decode(0x0470_CFE2).mnemonic == .undefined)
    }
}

/// Validates the stack-frame-adjust group.
@Suite("SVE predicate & control / stack-frame adjust")
struct SVEStackFrameAdjustDecodeTests {
    @Test func theVectorLengthAddReadsAndWritesGeneralRegisters() {
        let d = decode(0x0421_50A2)
        #expect(d.mnemonic == .addvl)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [.register(.x(2)), .register(.x(1)), .immediate(value: 5, width: 6)])
        #expect(d.semanticReads == RegisterSet.empty.inserting(.x(1)))
        #expect(d.semanticWrites == RegisterSet.empty.inserting(.x(2)))
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theVectorLengthAddKeepsTheStackPointerInItsMask() {
        let d = decode(0x043F_579F)
        #expect(d.mnemonic == .addvl)
        #expect(Array(d.operands) == [.register(.sp()), .register(.sp()), .immediate(value: -4, width: 6)])
        let sp = RegisterSet.empty.inserting(.sp())
        #expect(d.semanticReads == sp)
        #expect(d.semanticWrites == sp)
    }

    @Test func thePredicateLengthAddAndBothStreamingTwins() {
        let cases: [(UInt32, Mnemonic, Int64, ScalableEffect)] = [
            (0x0421_58A2, .addsvl, 5, .none),
            (0x0461_5402, .addpl, -32, .readsStreamingMode),
            (0x0461_5BE2, .addspl, 31, .none),
        ]
        for (encoding, mnemonic, immediate, effect) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(Array(d.operands) == [.register(.x(2)), .register(.x(1)), .immediate(value: immediate, width: 6)])
            #expect(
                d.scalableEffect == effect,
                "a streaming-length form does not depend on streaming mode; a plain one does",
            )
        }
    }

    @Test func theVectorLengthReadWritesOneRegisterFromAnImmediate() {
        let d = decode(0x04BF_5020)
        #expect(d.mnemonic == .rdvl)
        #expect(Array(d.operands) == [.register(.x(0)), .immediate(value: 1, width: 6)])
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == RegisterSet.empty.inserting(.x(0)))
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theStreamingVectorLengthReadCarriesNoStreamingDependence() {
        let d = decode(0x04BF_5FE0)
        #expect(d.mnemonic == .rdsvl)
        #expect(Array(d.operands) == [.register(.x(0)), .immediate(value: -1, width: 6)])
        #expect(d.scalableEffect == .none)
    }

    @Test func theVectorLengthReadTreatsRegisterThirtyOneAsZero() {
        let d = decode(0x04BF_501F)
        #expect(d.mnemonic == .rdvl)
        #expect(Array(d.operands) == [.register(.xzr()), .immediate(value: 0, width: 6)])
        #expect(d.semanticWrites == .empty)
    }

    @Test func theVectorLengthReadRejectsItsReservedFields() {
        #expect(decode(0x04FF_5020).mnemonic == .undefined)
        #expect(decode(0x04BE_5020).mnemonic == .undefined)
    }
}

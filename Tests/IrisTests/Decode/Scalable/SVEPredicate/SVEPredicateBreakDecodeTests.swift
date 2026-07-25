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

/// Validates the predicate break-and-partition group — BRKA/BRKB (with their
/// flag-setting twins), BRKN, BRKPA/BRKPB, PFIRST and PNEXT. Two things here are
/// easy to get wrong and expensive downstream: the merging break reads its own
/// destination and preserves inactive lanes (so it is a partial write, unlike
/// every other predicate write in the tier), and PFIRST's size field is not a
/// size at all — it is part of the opcode, so any other value is UNDEFINED.
@Suite("SVE predicate & control / break and partition")
struct SVEPredicateBreakDecodeTests {
    @Test func theZeroingBreakFullyWritesItsDestination() {
        let d = decode(0x2510_4443) // brka p3.b, p1/z, p2.b
        #expect(d.mnemonic == .brka)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [1, 2])
        #expect(predicates(d.scalableWrites) == [3])
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    @Test func theMergingBreakReadsItsDestinationAndWritesItPartially() {
        let d = decode(0x2510_4453) // brka p3.b, p1/m, p2.b
        #expect(d.mnemonic == .brka)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .merging, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
        ])
        #expect(predicates(d.scalableReads) == [1, 2, 3], "the merging form reads its destination")
        #expect(predicates(d.scalableWrites) == [3])
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func breakBeforeIsSelectedByBitTwentyThree() {
        let zeroing = decode(0x2590_4443) // brkb p3.b, p1/z, p2.b
        #expect(zeroing.mnemonic == .brkb)
        #expect(zeroing.scalableEffect == .readsStreamingMode)

        let merging = decode(0x2590_4453) // brkb p3.b, p1/m, p2.b
        #expect(merging.mnemonic == .brkb)
        #expect(merging.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(predicates(merging.scalableReads) == [1, 2, 3])
    }

    @Test func theFlagSettingBreaksAreZeroingOnly() {
        for (encoding, mnemonic) in [(UInt32(0x2550_4443), Mnemonic.brkas), (0x25D0_4443, .brkbs)] {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic)
            #expect(d.flagEffect == .nzcv)
            #expect(d.scalableEffect == .readsStreamingMode, "no flag-setting break is a partial write")
        }
        // There is no flag-setting merging break: that bit combination is a hole.
        #expect(decode(0x2550_4453).mnemonic == .undefined)
        #expect(decode(0x25D0_4453).mnemonic == .undefined)
    }

    @Test func theBreakRejectsItsReservedBits() {
        #expect(decode(0x2511_4443).mnemonic == .undefined) // bits 18:16
        #expect(decode(0x2510_4643).mnemonic == .undefined) // bit 9
    }

    @Test func theBreakIntoNextPartitionReadsAndFullyWritesItsTiedDestination() {
        let d = decode(0x2518_4443) // brkn p3.b, p1/z, p2.b, p3.b
        #expect(d.mnemonic == .brkn)
        #expect(d.flagEffect == .none)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b)),
        ], "the tied destination is reprinted as the fourth operand")
        #expect(predicates(d.scalableReads) == [1, 2, 3])
        #expect(predicates(d.scalableWrites) == [3])
        #expect(d.scalableEffect == .readsStreamingMode, "the whole register is selected, so the write is full")
    }

    @Test func theFlagSettingBreakIntoNextPartition() {
        let d = decode(0x2558_4443) // brkns p3.b, p1/z, p2.b, p3.b
        #expect(d.mnemonic == .brkns)
        #expect(d.flagEffect == .nzcv)
        #expect(d.operands.count == 4)
    }

    @Test func theBreakIntoNextPartitionRejectsItsReservedBits() {
        #expect(decode(0x2598_4443).mnemonic == .undefined) // bit 23
        #expect(decode(0x2518_4453).mnemonic == .undefined) // bit 4
    }

    @Test func theBreakPairFormsReadThreePredicatesAndWriteOne() {
        let cases: [(UInt32, Mnemonic, FlagEffect)] = [
            (0x2504_C443, .brkpa, .none),
            (0x2504_C453, .brkpb, .none),
            (0x2544_C443, .brkpas, .nzcv),
            (0x2544_C453, .brkpbs, .nzcv),
        ]
        for (encoding, mnemonic, flags) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == flags)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .zeroing, role: .governing)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, element: .b)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 4, element: .b)),
            ])
            #expect(predicates(d.scalableReads) == [1, 2, 4])
            #expect(predicates(d.scalableWrites) == [3])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func theBreakPairRejectsItsReservedBits() {
        #expect(decode(0x2584_C443).mnemonic == .undefined) // bit 23
        #expect(decode(0x2504_C643).mnemonic == .undefined) // bit 9
    }

    @Test func setFirstActiveLaneIsAPartialWriteOnItsTiedDestination() {
        let d = decode(0x2558_C043) // pfirst p3.b, p2, p3.b
        #expect(d.mnemonic == .pfirst)
        #expect(d.flagEffect == .nzcv)
        #expect(Array(d.operands) == [
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b, role: .result)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 2, role: .governing)),
            .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: .b)),
        ], "the governing predicate is bare; the tied destination is reprinted")
        #expect(predicates(d.scalableReads) == [2, 3])
        #expect(predicates(d.scalableWrites) == [3])
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func setFirstActiveLaneHardwiresItsSizeFieldAsOpcode() {
        // The two bits that are a size everywhere else are part of PFIRST's
        // opcode: only the value 01 is the instruction, and it is byte-element.
        #expect(decode(0x2518_C043).mnemonic == .undefined) // 00
        #expect(decode(0x2598_C043).mnemonic == .undefined) // 10
        #expect(decode(0x25D8_C043).mnemonic == .undefined) // 11
    }

    @Test func advanceToNextActiveLaneTakesEverySizeAndFullyWrites() {
        let cases: [(UInt32, ScalarSize)] = [
            (0x2519_C443, .b),
            (0x2559_C443, .h),
            (0x2599_C443, .s),
            (0x25D9_C443, .d),
        ]
        for (encoding, size) in cases {
            let d = decode(encoding)
            #expect(d.mnemonic == .pnext, "0x\(String(encoding, radix: 16))")
            #expect(d.flagEffect == .nzcv)
            #expect(Array(d.operands) == [
                .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: size, role: .result)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 2, role: .governing)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: 3, element: size)),
            ])
            #expect(predicates(d.scalableReads) == [2, 3], "the tied destination is read")
            #expect(predicates(d.scalableWrites) == [3])
            #expect(
                d.scalableEffect == .readsStreamingMode,
                "every lane is recomputed from zero, so the write is full",
            )
        }
    }

    @Test func thePartitionOpcodeRejectsEveryUnallocatedCombination() {
        #expect(decode(0x2558_C053).mnemonic == .undefined) // bit 4 set
        #expect(decode(0x255A_C043).mnemonic == .undefined) // bits 18:16 = 010
        #expect(decode(0x2558_C643).mnemonic == .undefined) // bits 10:9 = 11
    }
}

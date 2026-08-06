// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

private func predicates(_ set: ScalableRegisterSet) -> [UInt8] {
    (0 ..< 16).filter { set.containsPredicate(UInt8($0)) }.map(UInt8.init)
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the SVE2 integer delta at 0x45 outside the narrowing families.
@Suite("SVE integer / SVE2 widening, bit-permute, match, histogram")
struct SVEIntSVE2HighDecodeTests {
    private static let widening: [(UInt32, Mnemonic, String)] = [
        (0x4542_0020, .saddlb, "saddlb z0.h, z1.b, z2.b"),
        (0x4542_0420, .saddlt, "saddlt z0.h, z1.b, z2.b"),
        (0x4542_0820, .uaddlb, "uaddlb z0.h, z1.b, z2.b"),
        (0x4542_0C20, .uaddlt, "uaddlt z0.h, z1.b, z2.b"),
        (0x4542_1020, .ssublb, "ssublb z0.h, z1.b, z2.b"),
        (0x4542_1420, .ssublt, "ssublt z0.h, z1.b, z2.b"),
        (0x4542_1820, .usublb, "usublb z0.h, z1.b, z2.b"),
        (0x4542_1C20, .usublt, "usublt z0.h, z1.b, z2.b"),
        (0x4542_3020, .sabdlb, "sabdlb z0.h, z1.b, z2.b"),
        (0x4542_3420, .sabdlt, "sabdlt z0.h, z1.b, z2.b"),
        (0x4542_3820, .uabdlb, "uabdlb z0.h, z1.b, z2.b"),
        (0x4542_3C20, .uabdlt, "uabdlt z0.h, z1.b, z2.b"),
        (0x4542_6020, .sqdmullb, "sqdmullb z0.h, z1.b, z2.b"),
        (0x4542_6420, .sqdmullt, "sqdmullt z0.h, z1.b, z2.b"),
        (0x4542_7020, .smullb, "smullb z0.h, z1.b, z2.b"),
        (0x4542_7420, .smullt, "smullt z0.h, z1.b, z2.b"),
        (0x4542_7820, .umullb, "umullb z0.h, z1.b, z2.b"),
        (0x4542_7C20, .umullt, "umullt z0.h, z1.b, z2.b"),
    ]

    @Test func everyWideningArithmeticOpcodeReadsNarrowSources() {
        for (encoding, mnemonic, expected) in Self.widening {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [33, 34], "\(expected) writes fresh")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        #expect(decode(0x4502_0020).mnemonic == .undefined, "widening to a byte destination")
        #expect(decode(0x4542_2020).mnemonic == .undefined, "reserved opcode 8")
    }

    @Test func theAddSubWideFormsReadTheFirstSourceAtTheDestinationWidth() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4542_4020, .saddwb, "saddwb z0.h, z1.h, z2.b"),
            (0x4542_4420, .saddwt, "saddwt z0.h, z1.h, z2.b"),
            (0x4542_4820, .uaddwb, "uaddwb z0.h, z1.h, z2.b"),
            (0x4542_4C20, .uaddwt, "uaddwt z0.h, z1.h, z2.b"),
            (0x4542_5020, .ssubwb, "ssubwb z0.h, z1.h, z2.b"),
            (0x4542_5420, .ssubwt, "ssubwt z0.h, z1.h, z2.b"),
            (0x4542_5820, .usubwb, "usubwb z0.h, z1.h, z2.b"),
            (0x4542_5C20, .usubwt, "usubwt z0.h, z1.h, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func thePolynomialMultipliesOwnTheQuadwordFormAndAMidRangeHole() {
        #expect(text(0x4502_6820) == "pmullb z0.q, z1.d, z2.d")
        #expect(text(0x4502_6C20) == "pmullt z0.q, z1.d, z2.d")
        #expect(text(0x4542_6820) == "pmullb z0.h, z1.b, z2.b")
        #expect(text(0x45C2_6820) == "pmullb z0.d, z1.s, z2.s")
        #expect(decode(0x4582_6820).mnemonic == .undefined, "pmullb at the reserved sz=10")
    }

    @Test func theBitPermutesAndInterleavedLongsShareTheirRegion() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4502_B020, .bext, "bext z0.b, z1.b, z2.b"),
            (0x4502_B420, .bdep, "bdep z0.b, z1.b, z2.b"),
            (0x4502_B820, .bgrp, "bgrp z0.b, z1.b, z2.b"),
            (0x4542_8020, .saddlbt, "saddlbt z0.h, z1.b, z2.b"),
            (0x4542_8820, .ssublbt, "ssublbt z0.h, z1.b, z2.b"),
            (0x4542_8C20, .ssubltb, "ssubltb z0.h, z1.b, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x4502_8020).mnemonic == .undefined, "saddlbt at byte")
        #expect(decode(0x4542_8420).mnemonic == .undefined, "reserved misc opcode 0001")
        #expect(decode(0x4542_BC20).mnemonic == .undefined, "reserved misc opcode 1111")
    }

    @Test func theInterleavedXorPreservesTheOtherLaneParity() {
        let d = decode(0x4502_9020)
        #expect(d.mnemonic == .eorbt)
        #expect(text(0x4502_9020) == "eorbt z0.b, z1.b, z2.b")
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        #expect(canonicalIndices(d.semanticWrites) == [32])
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(decode(0x4502_9420).mnemonic == .eortb)
        #expect(text(0x4502_9420) == "eortb z0.b, z1.b, z2.b")
    }

    @Test func theCarryPropagatingAccumulatorsNeverTouchTheFlags() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4502_D020, .adclb, "adclb z0.s, z1.s, z2.s"),
            (0x4502_D420, .adclt, "adclt z0.s, z1.s, z2.s"),
            (0x4582_D020, .sbclb, "sbclb z0.s, z1.s, z2.s"),
            (0x4582_D420, .sbclt, "sbclt z0.s, z1.s, z2.s"),
            (0x4542_D020, .adclb, "adclb z0.d, z1.d, z2.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.flagEffect == .none, "\(expected) must not touch NZCV")
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    @Test func theAbsoluteDifferenceAccumulatorsSplitBottomTopAndSameWidth() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4542_C020, .sabalb, "sabalb z0.h, z1.b, z2.b"),
            (0x4542_C420, .sabalt, "sabalt z0.h, z1.b, z2.b"),
            (0x4542_C820, .uabalb, "uabalb z0.h, z1.b, z2.b"),
            (0x4542_CC20, .uabalt, "uabalt z0.h, z1.b, z2.b"),
            (0x4502_F820, .saba, "saba z0.b, z1.b, z2.b"),
            (0x4502_FC20, .uaba, "uaba z0.b, z1.b, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(expected) accumulates")
        }
        #expect(decode(0x4502_C020).mnemonic == .undefined, "sabalb at byte")
        #expect(decode(0x4502_E020).mnemonic == .undefined, "reserved absdiff opcode")
    }

    @Test func theIntegerMatmulsHaveOneReservedSizeSlot() {
        #expect(text(0x4502_9820) == "smmla z0.s, z1.b, z2.b")
        #expect(text(0x4582_9820) == "usmmla z0.s, z1.b, z2.b")
        #expect(text(0x45C2_9820) == "ummla z0.s, z1.b, z2.b")
        #expect(decode(0x4542_9820).mnemonic == .undefined, "matmul at the reserved sz=01")
        #expect(canonicalIndices(decode(0x4502_9820).semanticReads) == [32, 33, 34])
    }

    @Test func theAccumulateShiftsReadTheirDestinationButWriteItWhole() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4508_E020, .ssra, "ssra z0.b, z1.b, #8"),
            (0x4508_E420, .usra, "usra z0.b, z1.b, #8"),
            (0x4508_E820, .srsra, "srsra z0.b, z1.b, #8"),
            (0x4508_EC20, .ursra, "ursra z0.b, z1.b, #8"),
            (0x4580_E020, .ssra, "ssra z0.d, z1.d, #64"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33], "\(expected) accumulates")
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) rewrites every lane")
        }
        #expect(decode(0x4500_E020).mnemonic == .undefined, "accumulate shift with a zero tsz")
    }

    @Test func theInsertShiftsPreserveTheVacatedBits() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4508_F020, .sri, "sri z0.b, z1.b, #8"),
            (0x4508_F420, .sli, "sli z0.b, z1.b, #0"),
            (0x4580_F020, .sri, "sri z0.d, z1.d, #64"),
            (0x4540_F020, .sri, "sri z0.s, z1.s, #32"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33])
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "\(expected) preserves bits")
        }
    }

    @Test func theWideningShiftLeftsWriteEveryDestinationLane() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4508_A020, .sshllb, "sshllb z0.h, z1.b, #0"),
            (0x4508_A420, .sshllt, "sshllt z0.h, z1.b, #0"),
            (0x4508_A820, .ushllb, "ushllb z0.h, z1.b, #0"),
            (0x4508_AC20, .ushllt, "ushllt z0.h, z1.b, #0"),
            (0x4540_A020, .sshllb, "sshllb z0.d, z1.s, #0"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [33], "\(expected) reads only Zn")
            #expect(d.scalableEffect == .readsStreamingMode)
        }
        #expect(decode(0x4500_A020).mnemonic == .undefined, "shift-left-long with a zero tsz")
    }

    @Test func complexAdditionTakesZmFromTheLowFieldWithTwoRotations() {
        let d = decode(0x4500_D820)
        #expect(d.mnemonic == .cadd)
        #expect(text(0x4500_D820) == "cadd z0.b, z0.b, z1.b, #90")
        #expect(text(0x4500_DC20) == "cadd z0.b, z0.b, z1.b, #270")
        #expect(text(0x4501_D820) == "sqcadd z0.b, z0.b, z1.b, #90")
        #expect(d.operands[3] == .immediate(value: 90, width: 16))
        #expect(canonicalIndices(d.semanticReads) == [32, 33], "CADD is destructive")
    }

    @Test func matchWritesItsPredicateAndNZCVLikeTheCompares() {
        let d = decode(0x4522_8020)
        #expect(d.mnemonic == .match)
        #expect(text(0x4522_8020) == "match p0.b, p0/z, z1.b, z2.b")
        #expect(d.flagEffect == .nzcv)
        #expect(predicates(d.scalableReads) == [0])
        #expect(predicates(d.scalableWrites) == [0])
        #expect(canonicalIndices(d.semanticWrites) == [], "MATCH writes no Z register")
        #expect(decode(0x4522_8030).mnemonic == .nmatch)
        #expect(text(0x4522_8030) == "nmatch p0.b, p0/z, z1.b, z2.b")
        #expect(text(0x4562_8020) == "match p0.h, p0/z, z1.h, z2.h")
    }

    @Test func theHistogramFormsSplitOnTheirRegions() {
        let count = decode(0x45A2_C020)
        #expect(count.mnemonic == .histcnt)
        #expect(text(0x45A2_C020) == "histcnt z0.s, p0/z, z1.s, z2.s")
        #expect(text(0x45E2_C020) == "histcnt z0.d, p0/z, z1.d, z2.d")
        #expect(predicates(count.scalableReads) == [0], "HISTCNT is governed")
        #expect(canonicalIndices(count.semanticWrites) == [32])
        let segment = decode(0x4522_A020)
        #expect(segment.mnemonic == .histseg)
        #expect(text(0x4522_A020) == "histseg z0.b, z1.b, z2.b")
        #expect(segment.scalableReads == .empty, "HISTSEG is unpredicated")
    }
}

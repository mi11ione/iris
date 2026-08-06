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

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the SVE2 integer delta at 0x44.
@Suite("SVE integer / SVE2 saturating, multiply-add-long, dot, clamp")
struct SVEIntSVE2LowDecodeTests {
    private static let saturating: [(UInt32, Mnemonic)] = [
        (0x4402_8020, .srshl), (0x4403_8020, .urshl),
        (0x4406_8020, .srshlr), (0x4407_8020, .urshlr),
        (0x4408_8020, .sqshl), (0x4409_8020, .uqshl),
        (0x440A_8020, .sqrshl), (0x440B_8020, .uqrshl),
        (0x440C_8020, .sqshlr), (0x440D_8020, .uqshlr),
        (0x440E_8020, .sqrshlr), (0x440F_8020, .uqrshlr),
        (0x4410_8020, .shadd), (0x4411_8020, .uhadd),
        (0x4412_8020, .shsub), (0x4413_8020, .uhsub),
        (0x4414_8020, .srhadd), (0x4415_8020, .urhadd),
        (0x4416_8020, .shsubr), (0x4417_8020, .uhsubr),
        (0x4418_8020, .sqadd), (0x4419_8020, .uqadd),
        (0x441A_8020, .sqsub), (0x441B_8020, .uqsub),
        (0x441C_8020, .suqadd), (0x441D_8020, .usqadd),
        (0x441E_8020, .sqsubr), (0x441F_8020, .uqsubr),
    ]

    @Test func everySaturatingPredicatedOpcodeMergesDestructively() {
        for (encoding, mnemonic) in Self.saturating {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
            #expect(canonicalIndices(d.semanticReads) == [32, 33])
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.flagEffect == .none, "saturation is silent — no NZCV")
        }
        #expect(text(0x4402_8020) == "srshl z0.b, p0/m, z0.b, z1.b")
        #expect(text(0x4418_8020) == "sqadd z0.b, p0/m, z0.b, z1.b")
        for encoding: UInt32 in [0x4400_8020, 0x4401_8020, 0x4404_8020, 0x4405_8020] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func thePairwiseOpcodesLiveInTheBit13Half() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4410_A020, .subp, "subp z0.b, p0/m, z0.b, z1.b"),
            (0x4411_A020, .addp, "addp z0.b, p0/m, z0.b, z1.b"),
            (0x4414_A020, .smaxp, "smaxp z0.b, p0/m, z0.b, z1.b"),
            (0x4416_A020, .sminp, "sminp z0.b, p0/m, z0.b, z1.b"),
            (0x4417_A020, .uminp, "uminp z0.b, p0/m, z0.b, z1.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(decode(0x4412_A020).mnemonic == .undefined, "reserved pairwise opcode")
        #expect(decode(0x4418_A020).mnemonic == .undefined, "saturating opcode in the pairwise half")
    }

    @Test func theMultiplyAddLongFamilyWidensExceptTheRoundingDoublingPair() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4482_4020, .smlalb, "smlalb z0.s, z1.h, z2.h"),
            (0x4482_4420, .smlalt, "smlalt z0.s, z1.h, z2.h"),
            (0x4482_4820, .umlalb, "umlalb z0.s, z1.h, z2.h"),
            (0x4482_4C20, .umlalt, "umlalt z0.s, z1.h, z2.h"),
            (0x4482_5020, .smlslb, "smlslb z0.s, z1.h, z2.h"),
            (0x4482_5420, .smlslt, "smlslt z0.s, z1.h, z2.h"),
            (0x4482_5820, .umlslb, "umlslb z0.s, z1.h, z2.h"),
            (0x4482_5C20, .umlslt, "umlslt z0.s, z1.h, z2.h"),
            (0x4482_6020, .sqdmlalb, "sqdmlalb z0.s, z1.h, z2.h"),
            (0x4482_6420, .sqdmlalt, "sqdmlalt z0.s, z1.h, z2.h"),
            (0x4482_6820, .sqdmlslb, "sqdmlslb z0.s, z1.h, z2.h"),
            (0x4482_6C20, .sqdmlslt, "sqdmlslt z0.s, z1.h, z2.h"),
            (0x4482_0820, .sqdmlalbt, "sqdmlalbt z0.s, z1.h, z2.h"),
            (0x4482_0C20, .sqdmlslbt, "sqdmlslbt z0.s, z1.h, z2.h"),
            (0x4442_0820, .sqdmlalbt, "sqdmlalbt z0.h, z1.b, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(expected) reads its accumulator")
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) rewrites every lane")
        }
        #expect(text(0x4482_7020) == "sqrdmlah z0.s, z1.s, z2.s")
        #expect(text(0x4482_7420) == "sqrdmlsh z0.s, z1.s, z2.s")
        #expect(text(0x4402_7020) == "sqrdmlah z0.b, z1.b, z2.b")
        #expect(decode(0x4402_0820).mnemonic == .undefined)
        #expect(decode(0x4402_4020).mnemonic == .undefined)
    }

    @Test func theComplexFamilyCarriesQuarterRotations() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4482_1020, .cdot, "cdot z0.s, z1.b, z2.b, #0"),
            (0x4482_1C20, .cdot, "cdot z0.s, z1.b, z2.b, #270"),
            (0x4402_2020, .cmla, "cmla z0.b, z1.b, z2.b, #0"),
            (0x4402_3020, .sqrdcmlah, "sqrdcmlah z0.b, z1.b, z2.b, #0"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        }
        #expect(decode(0x4482_1C20).operands[3] == .immediate(value: 270, width: 16))
        #expect(decode(0x4442_1020).mnemonic == .undefined, "cdot at halfword")
        #expect(text(0x44C2_1020) == "cdot z0.d, z1.h, z2.h, #0")
    }

    @Test func theDotProductsPickTheirSourceWidthFromTheElement() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4482_0020, .sdot, "sdot z0.s, z1.b, z2.b"),
            (0x4482_0420, .udot, "udot z0.s, z1.b, z2.b"),
            (0x44C2_0020, .sdot, "sdot z0.d, z1.h, z2.h"),
            (0x4442_0020, .sdot, "sdot z0.h, z1.b, z2.b"),
            (0x4482_7820, .usdot, "usdot z0.s, z1.b, z2.b"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(expected) accumulates")
        }
        #expect(decode(0x4402_0020).mnemonic == .undefined, "dot at byte")
        #expect(decode(0x4402_7820).mnemonic == .undefined, "usdot away from word")
    }

    @Test func theTwoWayDotSplitsVectorFromIndexedOnTheSizeField() {
        #expect(text(0x4402_C820) == "sdot z0.s, z1.h, z2.h")
        #expect(text(0x4402_CC20) == "udot z0.s, z1.h, z2.h")
        #expect(text(0x4482_C820) == "sdot z0.s, z1.h, z2.h[0]")
        #expect(text(0x449A_C820) == "sdot z0.s, z1.h, z2.h[3]")
        #expect(decode(0x4442_C820).mnemonic == .undefined)
        let indexed = decode(0x449A_C820)
        #expect(indexed.operands[2] == .scalableVector(
            ScalableVectorRef(registerIndex: 2, element: .h, elementIndex: 3),
        ))
    }

    @Test func clampReadsItsDestinationYetWritesEveryLane() {
        let signed = decode(0x4402_C020)
        #expect(signed.mnemonic == .sclamp)
        #expect(text(0x4402_C020) == "sclamp z0.b, z1.b, z2.b")
        #expect(canonicalIndices(signed.semanticReads) == [32, 33, 34], "the clamped value lives in Zd")
        #expect(canonicalIndices(signed.semanticWrites) == [32])
        #expect(signed.scalableEffect == .readsStreamingMode, "every lane is recomputed — full write")
        #expect(decode(0x4402_C420).mnemonic == .uclamp)
        #expect(text(0x4402_C420) == "uclamp z0.b, z1.b, z2.b")
    }

    @Test func theSaturatingUnariesSplitOnTheirMergingBit() {
        let merging = decode(0x4408_A020)
        #expect(merging.mnemonic == .sqabs)
        #expect(text(0x4408_A020) == "sqabs z0.b, p0/m, z1.b")
        #expect(merging.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(merging.semanticReads) == [32, 33])
        let zeroing = decode(0x440A_A020)
        #expect(zeroing.mnemonic == .sqabs)
        #expect(text(0x440A_A020) == "sqabs z0.b, p0/z, z1.b")
        #expect(zeroing.scalableEffect == .readsStreamingMode)
        #expect(canonicalIndices(zeroing.semanticReads) == [33])
        #expect(decode(0x4409_A020).mnemonic == .sqneg)
    }

    @Test func theReciprocalEstimatesAreWordOnly() {
        #expect(text(0x4480_A020) == "urecpe z0.s, p0/m, z1.s")
        #expect(text(0x4481_A020) == "ursqrte z0.s, p0/m, z1.s")
        #expect(decode(0x4400_A020).mnemonic == .undefined, "urecpe at byte")
    }

    @Test func thePairwiseAccumulateWidensUnderItsPredicate() {
        let d = decode(0x4444_A020)
        #expect(d.mnemonic == .sadalp)
        #expect(text(0x4444_A020) == "sadalp z0.h, p0/m, z1.b")
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(d.semanticReads) == [32, 33])
        #expect(decode(0x4445_A020).mnemonic == .uadalp)
        #expect(decode(0x4404_A020).mnemonic == .undefined, "sadalp at byte")
        #expect(decode(0x444C_A020).mnemonic == .undefined, "reserved b19 slot")
        #expect(decode(0x4406_A020).mnemonic == .undefined, "reserved b18:17 = 11 slot")
    }

    @Test func theCheckedPointerFormsAreDoublewordOnly() {
        let mla = decode(0x44C2_D020)
        #expect(mla.mnemonic == .mlapt)
        #expect(text(0x44C2_D020) == "mlapt z0.d, z1.d, z2.d")
        #expect(canonicalIndices(mla.semanticReads) == [32, 33, 34])
        let mad = decode(0x44C1_D840)
        #expect(mad.mnemonic == .madpt)
        #expect(text(0x44C1_D840) == "madpt z0.d, z1.d, z2.d")
        #expect(canonicalIndices(mad.semanticReads) == [32, 33, 34])
        #expect(decode(0x4402_D020).mnemonic == .undefined, "mlapt below doubleword")
    }

    @Test func theLongAbsoluteDifferenceFormsAtThisTopByteHaveNoBottomTopSplit() {
        let d = decode(0x4442_D420)
        #expect(d.mnemonic == .sabal)
        #expect(text(0x4442_D420) == "sabal z0.h, z1.b, z2.b")
        #expect(decode(0x4442_DC20).mnemonic == .uabal)
        #expect(text(0x4442_DC20) == "uabal z0.h, z1.b, z2.b")
        #expect(decode(0x4402_D420).mnemonic == .undefined, "sabal at byte")
    }

    @Test func theReservedSubDispatchSlotIsAHole() {
        #expect(decode(0x4402_7C20).mnemonic == .undefined)
    }
}

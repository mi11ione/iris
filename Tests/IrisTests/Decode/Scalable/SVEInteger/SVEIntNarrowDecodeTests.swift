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

/// Validates the SVE2 narrowing families at 0x45.
@Suite("SVE integer / SVE2 narrowing")
struct SVEIntNarrowDecodeTests {
    @Test func theNarrowHighAddsSplitBottomFromTopOnBit10() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4562_6020, .addhnb, "addhnb z0.b, z1.h, z2.h"),
            (0x4562_6420, .addhnt, "addhnt z0.b, z1.h, z2.h"),
            (0x4562_6820, .raddhnb, "raddhnb z0.b, z1.h, z2.h"),
            (0x4562_6C20, .raddhnt, "raddhnt z0.b, z1.h, z2.h"),
            (0x4562_7020, .subhnb, "subhnb z0.b, z1.h, z2.h"),
            (0x4562_7420, .subhnt, "subhnt z0.b, z1.h, z2.h"),
            (0x4562_7820, .rsubhnb, "rsubhnb z0.b, z1.h, z2.h"),
            (0x4562_7C20, .rsubhnt, "rsubhnt z0.b, z1.h, z2.h"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        #expect(text(0x45E2_6020) == "addhnb z0.s, z1.d, z2.d")
        #expect(decode(0x4522_6020).mnemonic == .undefined, "narrow-high from a byte source")
    }

    @Test func aTopNarrowReadsItsDestinationAndABottomOneDoesNot() {
        let bottom = decode(0x4562_6020)
        #expect(canonicalIndices(bottom.semanticReads) == [33, 34])
        #expect(bottom.scalableEffect == .readsStreamingMode)
        let top = decode(0x4562_6420)
        #expect(canonicalIndices(top.semanticReads) == [32, 33, 34], "the top half preserves Zd")
        #expect(top.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(top.semanticWrites) == [32])
    }

    @Test func theSaturatingExtractsUseAStrictlyOneHotSize() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4528_4020, .sqxtnb, "sqxtnb z0.b, z1.h"),
            (0x4528_4420, .sqxtnt, "sqxtnt z0.b, z1.h"),
            (0x4528_4820, .uqxtnb, "uqxtnb z0.b, z1.h"),
            (0x4528_4C20, .uqxtnt, "uqxtnt z0.b, z1.h"),
            (0x4528_5020, .sqxtunb, "sqxtunb z0.b, z1.h"),
            (0x4528_5420, .sqxtunt, "sqxtunt z0.b, z1.h"),
            (0x4530_4020, .sqxtnb, "sqxtnb z0.h, z1.s"),
            (0x4560_4020, .sqxtnb, "sqxtnb z0.s, z1.d"),
        ]
        for (encoding, mnemonic, expected) in rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
        for encoding: UInt32 in [
            0x4520_4020,
            0x4538_4020,
            0x4568_4020,
            0x4528_5820,
        ] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
        let top = decode(0x4528_4420)
        #expect(canonicalIndices(top.semanticReads) == [32, 33])
        #expect(top.scalableEffect == [.readsStreamingMode, .partialWrite])
        let bottom = decode(0x4528_4020)
        #expect(canonicalIndices(bottom.semanticReads) == [33])
        #expect(bottom.scalableEffect == .readsStreamingMode)
    }

    @Test func theShiftNarrowsDecodeElementAndAmountJointly() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4528_0020, .sqshrunb, "sqshrunb z0.b, z1.h, #8"),
            (0x4528_0420, .sqshrunt, "sqshrunt z0.b, z1.h, #8"),
            (0x4528_0820, .sqrshrunb, "sqrshrunb z0.b, z1.h, #8"),
            (0x4528_0C20, .sqrshrunt, "sqrshrunt z0.b, z1.h, #8"),
            (0x4528_1020, .shrnb, "shrnb z0.b, z1.h, #8"),
            (0x4528_1420, .shrnt, "shrnt z0.b, z1.h, #8"),
            (0x4528_1820, .rshrnb, "rshrnb z0.b, z1.h, #8"),
            (0x4528_1C20, .rshrnt, "rshrnt z0.b, z1.h, #8"),
            (0x4528_2020, .sqshrnb, "sqshrnb z0.b, z1.h, #8"),
            (0x4528_2420, .sqshrnt, "sqshrnt z0.b, z1.h, #8"),
            (0x4528_2820, .sqrshrnb, "sqrshrnb z0.b, z1.h, #8"),
            (0x4528_2C20, .sqrshrnt, "sqrshrnt z0.b, z1.h, #8"),
            (0x4528_3020, .uqshrnb, "uqshrnb z0.b, z1.h, #8"),
            (0x4528_3420, .uqshrnt, "uqshrnt z0.b, z1.h, #8"),
            (0x4528_3820, .uqrshrnb, "uqrshrnb z0.b, z1.h, #8"),
            (0x4528_3C20, .uqrshrnt, "uqrshrnt z0.b, z1.h, #8"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.operands[2] == .immediate(value: 8, width: 8))
        }
        #expect(decode(0x4520_0020).mnemonic == .undefined, "shift-narrow with a zero tsz")
        let top = decode(0x4528_1420)
        #expect(top.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(top.semanticReads) == [32, 33])
    }

    @Test func theMultiVectorExtractsReadAConsecutiveEvenPair() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x4531_4040, .sqcvtn, "sqcvtn z0.h, { z2.s, z3.s }"),
            (0x4531_4840, .uqcvtn, "uqcvtn z0.h, { z2.s, z3.s }"),
            (0x4531_5040, .sqcvtun, "sqcvtun z0.h, { z2.s, z3.s }"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [34, 35], "\(expected) reads both pair members")
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode, "a pair-to-one narrow writes every lane")
            #expect(d.operands[1] == .scalableVectorGroup(ScalableVectorGroup(
                firstIndex: 2, count: 2, element: .s, layout: .consecutive,
            )))
        }
        #expect(decode(0x4531_5840).mnemonic == .undefined, "reserved multi-vector-extract opcode")
    }

    @Test func theMultiVectorShiftsCarryTheirAmountAfterThePair() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x45A8_0040, .sqshrn, "sqshrn z0.b, { z2.h, z3.h }, #8"),
            (0x45A8_0840, .sqrshrun, "sqrshrun z0.b, { z2.h, z3.h }, #8"),
            (0x45A8_1040, .uqshrn, "uqshrn z0.b, { z2.h, z3.h }, #8"),
            (0x45A8_2040, .sqshrun, "sqshrun z0.b, { z2.h, z3.h }, #8"),
            (0x45A8_2840, .sqrshrn, "sqrshrn z0.b, { z2.h, z3.h }, #8"),
            (0x45A8_3840, .uqrshrn, "uqrshrn z0.b, { z2.h, z3.h }, #8"),
            (0x45B0_0040, .sqshrn, "sqshrn z0.h, { z2.s, z3.s }, #16"),
        ]
        for (encoding, mnemonic, expected) in rows {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.operands[2] == .immediate(
                value: expected.hasSuffix("#16") ? 16 : 8, width: 8,
            ))
        }
        #expect(decode(0x45A8_1840).mnemonic == .undefined, "reserved multi-vector-shift opcode 011")
        #expect(decode(0x45A8_3040).mnemonic == .undefined, "reserved multi-vector-shift opcode 110")
        #expect(decode(0x45A0_0040).mnemonic == .undefined, "multi-vector shift with a zero tsz")
    }

    @Test func theOddPairFieldStillDecodesAnEvenAlignedPair() {
        let d = decode(0x45A8_03C0)
        #expect(text(0x45A8_03C0) == "sqshrn z0.b, { z30.h, z31.h }, #8")
        #expect(canonicalIndices(d.semanticReads) == [62, 63])
    }
}

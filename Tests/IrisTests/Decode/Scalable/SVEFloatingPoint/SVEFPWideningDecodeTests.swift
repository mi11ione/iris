// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// Validates the widening multiply/dot/matrix cluster at 0x64 bit21=1.
@Suite("SVE floating-point / widening, dot, and matrix multiply")
struct SVEFPWideningDecodeTests {
    private static let wideningBase: UInt32 = 0x64A2_8020

    @Test func everyWideningLongMlaVectorFormDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0, .fmlalb, "fmlalb"),
            (1 << 10, .fmlalt, "fmlalt"),
            (1 << 13, .fmlslb, "fmlslb"),
            ((1 << 13) | (1 << 10), .fmlslt, "fmlslt"),
            (1 << 22, .bfmlalb, "bfmlalb"),
            ((1 << 22) | (1 << 10), .bfmlalt, "bfmlalt"),
            ((1 << 22) | (1 << 13), .bfmlslb, "bfmlslb"),
            ((1 << 22) | (1 << 13) | (1 << 10), .bfmlslt, "bfmlslt"),
        ]
        for (delta, mnemonic, name) in rows {
            let encoding = Self.wideningBase | delta
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.s, z1.h, z2.h")
            #expect(d.scalableEffect == .readsStreamingMode, "long MLA is a full-write accumulator")
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(name) reads the accumulator")
        }
    }

    private static let wideningIndexedBase: UInt32 = 0x64A2_4020

    @Test func wideningLongMlaIndexedPacksItsThreeBitLane() {
        #expect(decode(Self.wideningIndexedBase).mnemonic == .fmlalb)
        #expect(text(Self.wideningIndexedBase) == "fmlalb z0.s, z1.h, z2.h[0]")
        #expect(text(Self.wideningIndexedBase | (1 << 11)) == "fmlalb z0.s, z1.h, z2.h[1]")
        #expect(text(Self.wideningIndexedBase | (1 << 19)) == "fmlalb z0.s, z1.h, z2.h[2]")
        #expect(text(Self.wideningIndexedBase | (1 << 20)) == "fmlalb z0.s, z1.h, z2.h[4]")
        #expect(text(Self.wideningIndexedBase | (1 << 13)) == "fmlslb z0.s, z1.h, z2.h[0]")
        #expect(text(Self.wideningIndexedBase | (1 << 22)) == "bfmlalb z0.s, z1.h, z2.h[0]")
    }

    private static let dotBase: UInt32 = 0x6422_8020

    @Test func dotProductsSelectSourcesOnBitTwentyTwoAndBitTen() {
        #expect(text(Self.dotBase) == "fdot z0.s, z1.h, z2.h")
        #expect(text(Self.dotBase | (1 << 22)) == "bfdot z0.s, z1.h, z2.h")
        #expect(text(Self.dotBase | (1 << 10)) == "fdot z0.h, z1.b, z2.b")
        #expect(text(Self.dotBase | (1 << 10) | (1 << 22)) == "fdot z0.s, z1.b, z2.b")
        let d = decode(Self.dotBase)
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        #expect(d.scalableEffect == .readsStreamingMode)
    }

    private static let dotIndexedBase: UInt32 = 0x6422_4020

    @Test func dotProductIndexedDecodes() {
        #expect(decode(Self.dotIndexedBase).mnemonic == .fdot)
        #expect(text(Self.dotIndexedBase) == "fdot z0.s, z1.h, z2.h[0]")
        #expect(text(Self.dotIndexedBase | (0b11 << 19)) == "fdot z0.s, z1.h, z2.h[3]")
        #expect(text(Self.dotIndexedBase | (1 << 22)) == "bfdot z0.s, z1.h, z2.h[0]")
    }

    private static let fp8DotIndexedBase: UInt32 = 0x6422_4420

    @Test func fp8DotIndexedPacksIndexPerDestination() {
        #expect(decode(Self.fp8DotIndexedBase).mnemonic == .fdot)
        #expect(text(Self.fp8DotIndexedBase) == "fdot z0.h, z1.b, z2.b[0]")
        #expect(text(Self.fp8DotIndexedBase | (1 << 11)) == "fdot z0.h, z1.b, z2.b[1]")
        #expect(text(Self.fp8DotIndexedBase | (1 << 20)) == "fdot z0.h, z1.b, z2.b[4]")
        let sForm = Self.fp8DotIndexedBase | (1 << 22)
        #expect(text(sForm) == "fdot z0.s, z1.b, z2.b[0]")
        #expect(text(sForm | (0b11 << 19)) == "fdot z0.s, z1.b, z2.b[3]")
        #expect(decode(sForm | (1 << 11)).mnemonic == .undefined, "S form bit11 must be zero")
    }

    private static let fp8MlaBase: UInt32 = 0x6422_8820

    @Test func fp8MlaVectorSpansLongAndLongLongForms() {
        let longLong: [(UInt32, Mnemonic, String)] = [
            (0b00, .fmlallbb, "fmlallbb"), (0b01, .fmlallbt, "fmlallbt"),
            (0b10, .fmlalltb, "fmlalltb"), (0b11, .fmlalltt, "fmlalltt"),
        ]
        for (sel, mnemonic, name) in longLong {
            let encoding = Self.fp8MlaBase | (sel << 12)
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.s, z1.b, z2.b")
        }
        let long = Self.fp8MlaBase | (1 << 23)
        #expect(text(long) == "fmlalb z0.h, z1.b, z2.b")
        #expect(text(long | (1 << 12)) == "fmlalt z0.h, z1.b, z2.b")
        #expect(decode(long | (1 << 13)).mnemonic == .undefined, "long form bit13 must be zero")
    }

    private static let fp8LongIndexedBase: UInt32 = 0x6422_5020

    @Test func fp8LongIndexedDecodes() {
        #expect(decode(Self.fp8LongIndexedBase).mnemonic == .fmlalb)
        #expect(text(Self.fp8LongIndexedBase) == "fmlalb z0.h, z1.b, z2.b[0]")
        #expect(text(Self.fp8LongIndexedBase | (1 << 23)) == "fmlalt z0.h, z1.b, z2.b[0]")
        #expect(text(Self.fp8LongIndexedBase | (0b11 << 10)) == "fmlalb z0.h, z1.b, z2.b[3]")
        #expect(text(Self.fp8LongIndexedBase | (0b11 << 19)) == "fmlalb z0.h, z1.b, z2.b[12]")
    }

    private static let fp8LongLongIndexedBase: UInt32 = 0x6422_C020

    @Test func fp8LongLongIndexedDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b00, .fmlallbb, "fmlallbb"), (0b01, .fmlallbt, "fmlallbt"),
            (0b10, .fmlalltb, "fmlalltb"), (0b11, .fmlalltt, "fmlalltt"),
        ]
        for (sel, mnemonic, name) in rows {
            let encoding = Self.fp8LongLongIndexedBase | (sel << 22)
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.s, z1.b, z2.b[0]")
        }
        #expect(text(Self.fp8LongLongIndexedBase | (0b11 << 10)) == "fmlallbb z0.s, z1.b, z2.b[3]")
    }

    private static let matrixBase: UInt32 = 0x6422_E020

    @Test func theMatrixTableSpansEveryFormAndSize() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0, .fmmla, "fmmla z0.s, z1.b, z2.b"),
            (1 << 10, .fmmla, "fmmla z0.s, z1.h, z2.h"),
            (1 << 22, .fmmla, "fmmla z0.h, z1.b, z2.b"),
            ((1 << 22) | (1 << 10), .bfmmla, "bfmmla z0.s, z1.h, z2.h"),
            (2 << 22, .fmmla, "fmmla z0.h, z1.h, z2.h"),
            ((2 << 22) | (1 << 10), .fmmla, "fmmla z0.s, z1.s, z2.s"),
            (3 << 22, .bfmmla, "bfmmla z0.h, z1.h, z2.h"),
            ((3 << 22) | (1 << 10), .fmmla, "fmmla z0.d, z1.d, z2.d"),
        ]
        for (delta, mnemonic, expected) in rows {
            let encoding = Self.matrixBase | delta
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == .readsStreamingMode, "matrix multiply is a full-write accumulator")
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        }
    }
}

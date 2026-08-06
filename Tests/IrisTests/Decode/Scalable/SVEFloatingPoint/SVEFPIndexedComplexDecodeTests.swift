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

/// Validates the complex FP and indexed multiply forms.
@Suite("SVE floating-point / complex and indexed multiply")
struct SVEFPIndexedComplexDecodeTests {
    private static let fcaddBase: UInt32 = 0x6440_8420

    @Test func fcaddSelectsBetweenNinetyAndTwoSeventy() {
        let d = decode(Self.fcaddBase)
        #expect(d.mnemonic == .fcadd)
        #expect(text(Self.fcaddBase) == "fcadd z0.h, p1/m, z0.h, z1.h, #90")
        #expect(text(Self.fcaddBase | (1 << 16)) == "fcadd z0.h, p1/m, z0.h, z1.h, #270")
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "fcadd is merging")
        #expect(canonicalIndices(d.semanticReads) == [32, 33], "fcadd reads Zdn and Zm")
        #expect(decode(Self.fcaddBase | (1 << 17)).mnemonic == .undefined, "bits[20:17] must be zero")
        #expect(decode(Self.fcaddBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }

    private static let fcmlaVectorBase: UInt32 = 0x6442_0420

    @Test func fcmlaVectorRendersEachRotation() {
        let rows: [(UInt32, String)] = [
            (0b00, "#0"), (0b01, "#90"), (0b10, "#180"), (0b11, "#270"),
        ]
        for (rot, degrees) in rows {
            let encoding = Self.fcmlaVectorBase | (rot << 13)
            let d = decode(encoding)
            #expect(d.mnemonic == .fcmla, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "fcmla z0.h, p1/m, z1.h, z2.h, \(degrees)")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "fcmla vector is merging")
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "reads Zda, Zn, Zm")
        }
        #expect(decode(Self.fcmlaVectorBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }

    private static let fcmlaIndexedBase: UInt32 = 0x64A2_1020

    @Test func fcmlaIndexedIsAFullWriteAccumulatorWithPerSizePacking() {
        let d = decode(Self.fcmlaIndexedBase)
        #expect(d.mnemonic == .fcmla)
        #expect(text(Self.fcmlaIndexedBase) == "fcmla z0.h, z1.h, z2.h[0], #0")
        #expect(text(Self.fcmlaIndexedBase | (1 << 10)) == "fcmla z0.h, z1.h, z2.h[0], #90")
        #expect(text(Self.fcmlaIndexedBase | (1 << 19)) == "fcmla z0.h, z1.h, z2.h[1], #0")
        #expect(d.scalableEffect == .readsStreamingMode, "indexed accumulator is a full write")
        #expect(canonicalIndices(d.semanticReads) == [32, 33, 34])
        let sForm = Self.fcmlaIndexedBase | (1 << 22)
        #expect(text(sForm) == "fcmla z0.s, z1.s, z2.s[0], #0")
        #expect(text(sForm | (1 << 20)) == "fcmla z0.s, z1.s, z2.s[1], #0")
    }

    private static let indexedFmaBase: UInt32 = 0x6422_0020

    @Test func indexedFmaSelectsMnemonicOnBf16AndSubtract() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0, .fmla, "fmla"),
            (1 << 10, .fmls, "fmls"),
            (1 << 11, .bfmla, "bfmla"),
            ((1 << 10) | (1 << 11), .bfmls, "bfmls"),
        ]
        for (delta, mnemonic, name) in rows {
            let encoding = Self.indexedFmaBase | delta
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, z1.h, z2.h[0]")
            #expect(d.scalableEffect == .readsStreamingMode)
            #expect(canonicalIndices(d.semanticReads) == [32, 33, 34], "\(name) reads the accumulator")
        }
        #expect(decode(Self.indexedFmaBase | (1 << 11) | (1 << 23)).mnemonic == .undefined)
    }

    @Test func indexedFmaPacksTheLaneIndexPerSize() {
        #expect(text(Self.indexedFmaBase | (0b11 << 19)) == "fmla z0.h, z1.h, z2.h[3]")
        #expect(text(Self.indexedFmaBase | (1 << 22)) == "fmla z0.h, z1.h, z2.h[4]")
        let sForm = Self.indexedFmaBase | (1 << 23)
        #expect(text(sForm) == "fmla z0.s, z1.s, z2.s[0]")
        #expect(text(sForm | (0b11 << 19)) == "fmla z0.s, z1.s, z2.s[3]")
        let dForm = Self.indexedFmaBase | (0b11 << 22)
        #expect(text(dForm) == "fmla z0.d, z1.d, z2.d[0]")
        #expect(text(dForm | (1 << 20)) == "fmla z0.d, z1.d, z2.d[1]")
    }

    private static let indexedFmulBase: UInt32 = 0x6422_2020

    @Test func indexedFmulDoesNotReadItsDestination() {
        let d = decode(Self.indexedFmulBase)
        #expect(d.mnemonic == .fmul)
        #expect(text(Self.indexedFmulBase) == "fmul z0.h, z1.h, z2.h[0]")
        #expect(canonicalIndices(d.semanticReads) == [33, 34], "fmul reads Zn and Zm, not the destination")
        #expect(text(Self.indexedFmulBase | (1 << 11)) == "bfmul z0.h, z1.h, z2.h[0]")
        #expect(decode(Self.indexedFmulBase | (1 << 11) | (1 << 23)).mnemonic == .undefined)
    }
}

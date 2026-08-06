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

/// Validates FP compare to predicate, vector-register and compare-with-zero.
@Suite("SVE floating-point / compare to predicate")
struct SVEFPCompareDecodeTests {
    private static let vectorBase: UInt32 = 0x6543_4445

    @Test func everyVectorCompareSelectorDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x0000, .fcmge, "fcmge"),
            (0x0010, .fcmgt, "fcmgt"),
            (0x2000, .fcmeq, "fcmeq"),
            (0x2010, .fcmne, "fcmne"),
            (0x8000, .fcmuo, "fcmuo"),
            (0x8010, .facge, "facge"),
            (0xA010, .facgt, "facgt"),
        ]
        for (delta, mnemonic, name) in rows {
            let encoding = Self.vectorBase | delta
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) p5.h, p1/z, z2.h, z3.h")
            #expect(d.flagEffect == .none, "\(name) must never touch NZCV")
            #expect(canonicalIndices(d.semanticReads) == [34, 35], "\(name) reads Zn and Zm only")
            #expect(canonicalIndices(d.semanticWrites) == [], "\(name) writes no Z register")
            #expect(d.scalableWrites.predicateMask == (1 << 5), "\(name) writes Pd")
            #expect(d.scalableReads.predicateMask == (1 << 1), "\(name) reads Pg")
            #expect(d.scalableEffect == .readsStreamingMode, "a fresh Pd is a full write")
        }
        #expect(decode(Self.vectorBase | 0xA000).mnemonic == .undefined)
        #expect(decode(Self.vectorBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }

    @Test func theVectorSwapAliasesAreNeverEmitted() {
        let trap: Set<Mnemonic> = [.fcmle, .fcmlt]
        let cleared: UInt32 = 0x6503_4445
        for sz: UInt32 in [0b01, 0b10, 0b11] {
            for selector: UInt32 in 0 ..< 8 {
                let sel = ((selector & 0b100) << 13) | ((selector & 0b010) << 12) | ((selector & 0b001) << 4)
                let encoding = cleared | (sz << 22) | sel
                #expect(!trap.contains(decode(encoding).mnemonic), "0x\(String(encoding, radix: 16)) emitted a swap alias")
            }
        }
    }

    private static let zeroBase: UInt32 = 0x6550_2445

    @Test func everyCompareWithZeroSelectorDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0x00000, .fcmge, "fcmge"),
            (0x00010, .fcmgt, "fcmgt"),
            (0x10000, .fcmlt, "fcmlt"),
            (0x10010, .fcmle, "fcmle"),
            (0x20000, .fcmeq, "fcmeq"),
            (0x30000, .fcmne, "fcmne"),
        ]
        for (delta, mnemonic, name) in rows {
            let encoding = Self.zeroBase | delta
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) p5.h, p1/z, z2.h, #0.0")
            #expect(d.flagEffect == .none)
            #expect(canonicalIndices(d.semanticReads) == [34], "compare-with-zero reads only Zn")
            #expect(d.scalableWrites.predicateMask == (1 << 5))
        }
        #expect(decode(Self.zeroBase | 0x20010).mnemonic == .undefined)
        #expect(decode(Self.zeroBase | 0x30010).mnemonic == .undefined)
    }

    @Test func compareWithZeroRejectsItsFixedFieldAndSizeZero() {
        #expect(decode(Self.zeroBase | (1 << 18)).mnemonic == .undefined, "bit18 must be zero")
        #expect(decode(Self.zeroBase & ~(UInt32(0b11) << 22)).mnemonic == .undefined, "sz=00 hole")
    }

    @Test func compareWithZeroTakesEverySize() {
        let base = Self.zeroBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b01 << 22)) == "fcmge p5.h, p1/z, z2.h, #0.0")
        #expect(text(base | (0b10 << 22)) == "fcmge p5.s, p1/z, z2.s, #0.0")
        #expect(text(base | (0b11 << 22)) == "fcmge p5.d, p1/z, z2.d, #0.0")
    }
}

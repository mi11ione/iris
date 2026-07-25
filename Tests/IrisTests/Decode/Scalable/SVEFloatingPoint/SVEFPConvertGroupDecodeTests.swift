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

/// Validates G13, the FP8 and multi-vector convert cluster at 0x65: the
/// single-source FP8 up-converts to half precision (F1CVT/F2CVT/BF1CVT/BF2CVT
/// and their odd-input LT twins), the pair down-converts to FP8 bytes
/// (FCVTN/FCVTNB/BFCVTN and the top-half FCVTNT), the FP8 integer up-converts
/// (SCVTF/UCVTF ± LT), and the SVE2p2 pair int down-converts (FCVTZSN/FCVTZUN).
/// Pair sources render as consecutive `{ z2n.T, z2n+1.T }` groups whose 4-bit
/// base field is the pair base halved, and only FCVTNT is a preserving write.
@Suite("SVE floating-point / FP8 and multi-vector converts")
struct SVEFPConvertGroupDecodeTests {
    /// f1cvt z0.h, z1.b — G13a base (selector 00, even input).
    private static let singleBase: UInt32 = 0x6508_3020

    @Test func everyFp8SingleConvertDecodes() {
        let rows: [(UInt32, Bool, Mnemonic, String)] = [
            (0b00, false, .f1cvt, "f1cvt"), (0b00, true, .f1cvtlt, "f1cvtlt"),
            (0b01, false, .f2cvt, "f2cvt"), (0b01, true, .f2cvtlt, "f2cvtlt"),
            (0b10, false, .bf1cvt, "bf1cvt"), (0b10, true, .bf1cvtlt, "bf1cvtlt"),
            (0b11, false, .bf2cvt, "bf2cvt"), (0b11, true, .bf2cvtlt, "bf2cvtlt"),
        ]
        for (selector, odd, mnemonic, name) in rows {
            let encoding = Self.singleBase | (selector << 10) | (odd ? (1 << 16) : 0)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, z1.b")
            #expect(canonicalIndices(d.semanticReads) == [33])
            #expect(canonicalIndices(d.semanticWrites) == [32])
            #expect(d.scalableEffect == .readsStreamingMode)
        }
    }

    /// fcvtn z0.b, { z2.h, z3.h } — G13b/c base (selector 00, pair base 2).
    private static let downPairBase: UInt32 = 0x650A_3040

    @Test func everyPairDownConvertDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b00, .fcvtn, "fcvtn z0.b, { z2.h, z3.h }"),
            (0b01, .fcvtnb, "fcvtnb z0.b, { z2.s, z3.s }"),
            (0b10, .bfcvtn, "bfcvtn z0.b, { z2.h, z3.h }"),
        ]
        for (selector, mnemonic, expected) in rows {
            let encoding = Self.downPairBase | (selector << 10)
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == [34, 35], "the pair source reads both members")
            #expect(d.scalableEffect == .readsStreamingMode, "the bottom-narrow forms are full writes")
        }
        #expect(decode(Self.downPairBase | (1 << 5)).mnemonic == .undefined, "bit5 must be zero")
    }

    @Test func theTopHalfPairDownConvertPreservesTheDestination() {
        let encoding = Self.downPairBase | (0b11 << 10) // fcvtnt
        let d = decode(encoding)
        #expect(d.mnemonic == .fcvtnt)
        #expect(text(encoding) == "fcvtnt z0.b, { z2.s, z3.s }")
        #expect(canonicalIndices(d.semanticReads) == [32, 34, 35], "fcvtnt reads the destination too")
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func thePairBaseFieldIsHalvedAndConsecutive() {
        // The 4-bit field at bits[9:6] carries the pair base ÷ 2; field 7 → z14.
        let encoding = (Self.downPairBase & ~(UInt32(0xF) << 6)) | (7 << 6)
        #expect(text(encoding) == "fcvtn z0.b, { z14.h, z15.h }")
    }

    /// scvtf z0.h, z1.b — G13e base (selector 00, dest .h).
    private static let upConvertBase: UInt32 = 0x654C_3020

    @Test func everyFp8IntegerUpConvertDecodes() {
        let rows: [(UInt32, Mnemonic, String)] = [
            (0b00, .scvtf, "scvtf"), (0b01, .ucvtf, "ucvtf"),
            (0b10, .scvtflt, "scvtflt"), (0b11, .ucvtflt, "ucvtflt"),
        ]
        for (selector, mnemonic, name) in rows {
            let encoding = Self.upConvertBase | (selector << 10)
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == "\(name) z0.h, z1.b")
        }
        // The destination width climbs and the source is always one step below.
        let base = Self.upConvertBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b10 << 22)) == "scvtf z0.s, z1.h")
        #expect(text(base | (0b11 << 22)) == "scvtf z0.d, z1.s")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
    }

    /// fcvtzsn z0.h, { z2.s, z3.s } — G13d base (fcvtzsn, src .s).
    private static let intDownBase: UInt32 = 0x658D_3040

    @Test func everyPairIntDownConvertDecodes() {
        #expect(decode(Self.intDownBase).mnemonic == .fcvtzsn)
        #expect(text(Self.intDownBase) == "fcvtzsn z0.h, { z2.s, z3.s }")
        #expect(text(Self.intDownBase | (1 << 10)) == "fcvtzun z0.h, { z2.s, z3.s }")
        // src size climbs; the destination is one step below.
        let base = Self.intDownBase & ~(UInt32(0b11) << 22)
        #expect(text(base | (0b01 << 22)) == "fcvtzsn z0.b, { z2.h, z3.h }")
        #expect(text(base | (0b11 << 22)) == "fcvtzsn z0.s, { z2.d, z3.d }")
        #expect(decode(Self.intDownBase | (1 << 5)).mnemonic == .undefined, "bit5 must be zero")
        #expect(decode(base).mnemonic == .undefined, "sz=00 hole")
    }
}

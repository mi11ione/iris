// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0, features: .scalable)
}

private func text(_ e: UInt32) -> String {
    decode(e).text
}

private func canonicalIndices(_ set: RegisterSet) -> [Int] {
    (0 ..< 64).filter { (set.mask >> UInt64($0)) & 1 == 1 }
}

/// A merging-unary word (G11) with the given bits[23:16] form key, Pg=1, Zn=1,
/// Zd=0.
private func merging(_ key: UInt8) -> UInt32 {
    0x6500_0000 | (UInt32(key) << 16) | 0xA000 | (1 << 10) | (1 << 5)
}

/// A zeroing-unary word (G14) with the given (bits[23:16], bits[15:13]) form
/// key, Pg=1, Zn=1, Zd=0.
private func zeroing(_ key: UInt8, _ low: UInt32) -> UInt32 {
    0x6400_0000 | (UInt32(key) << 16) | (low << 13) | (1 << 10) | (1 << 5)
}

/// A convert-precision word (G15) for the form key with the given qualifier
/// (bit19 = merging), Pg=1, Zn=1, Zd=0.
private func convertPrecision(_ key: UInt8, merging: Bool) -> UInt32 {
    let byte1 = UInt32(key) | (merging ? 0x08 : 0)
    return 0x6400_0000 | (byte1 << 16) | 0xA000 | (1 << 10) | (1 << 5)
}

/// Validates the predicated unary/convert surface: G11 the merging `/M` class
/// (`sve_fp_2op_p_zd`), G14 the SVE2p2 zeroing `/Z` twins
/// (`sve_fp_z2op_p_zd`), and G15 the convert-precision group
/// (`sve2_fp_convert_precision`). The conversions render true cross-size
/// operand pairs; merging forms read the destination and set partialWrite,
/// zeroing forms are full writes — except the top-half converts FCVTNT/
/// FCVTXNT/BFCVTNT, which preserve the untouched halves under BOTH qualifiers,
/// and FCVTLT, which follows the plain `/M` rule.
@Suite("SVE floating-point / predicated unary and convert-precision")
struct SVEFPUnaryDecodeTests {
    @Test func mergingConversionsRenderCrossSizeOperands() {
        let rows: [(UInt8, Mnemonic, String)] = [
            (0x88, .fcvt, "fcvt z0.h, p1/m, z1.s"),
            (0x89, .fcvt, "fcvt z0.s, p1/m, z1.h"),
            (0xC9, .fcvt, "fcvt z0.d, p1/m, z1.h"),
            (0xCA, .fcvt, "fcvt z0.s, p1/m, z1.d"),
            (0xCB, .fcvt, "fcvt z0.d, p1/m, z1.s"),
            (0x0A, .fcvtx, "fcvtx z0.s, p1/m, z1.d"),
            (0x8A, .bfcvt, "bfcvt z0.h, p1/m, z1.s"),
            (0x5C, .fcvtzs, "fcvtzs z0.s, p1/m, z1.h"),
            (0xD0, .scvtf, "scvtf z0.d, p1/m, z1.s"),
        ]
        for (key, mnemonic, expected) in rows {
            let d = decode(merging(key))
            #expect(d.mnemonic == mnemonic, "key 0x\(String(key, radix: 16))")
            #expect(text(merging(key)) == expected)
        }
    }

    @Test func mergingUnaryFormsCoverEveryElementwiseFamily() {
        let rows: [(UInt8, String)] = [
            (0x40, "frintn z0.h, p1/m, z1.h"), (0x41, "frintp z0.h, p1/m, z1.h"),
            (0x42, "frintm z0.h, p1/m, z1.h"), (0x43, "frintz z0.h, p1/m, z1.h"),
            (0x44, "frinta z0.h, p1/m, z1.h"), (0x46, "frintx z0.h, p1/m, z1.h"),
            (0x47, "frinti z0.h, p1/m, z1.h"),
            (0x4C, "frecpx z0.h, p1/m, z1.h"), (0x4D, "fsqrt z0.h, p1/m, z1.h"),
            (0x1A, "flogb z0.h, p1/m, z1.h"), (0x1C, "flogb z0.s, p1/m, z1.s"),
            (0x10, "frint32z z0.s, p1/m, z1.s"), (0x11, "frint32x z0.s, p1/m, z1.s"),
            (0x14, "frint64z z0.s, p1/m, z1.s"), (0x17, "frint64x z0.d, p1/m, z1.d"),
            (0x52, "scvtf z0.h, p1/m, z1.h"), (0x53, "ucvtf z0.h, p1/m, z1.h"),
        ]
        for (key, expected) in rows {
            #expect(text(merging(key)) == expected, "key 0x\(String(key, radix: 16))")
        }
    }

    @Test func mergingUnaryIsADestinationReadingPartialWrite() {
        let d = decode(merging(0x4D)) // fsqrt z0.h
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(d.semanticReads) == [32, 33], "/m reads the destination and source")
        #expect(canonicalIndices(d.semanticWrites) == [32])
    }

    @Test func reservedMergingFormKeysAreHoles() {
        // Keys with bit5 set carry bit21=1 and route elsewhere, so a reserved
        // merging-form key must keep bit5 clear to reach this decoder.
        for key: UInt8 in [0x00, 0x01, 0x45, 0x90, 0x9E] {
            #expect(decode(merging(key)).mnemonic == .undefined, "key 0x\(String(key, radix: 16)) is reserved")
        }
    }

    @Test func zeroingConversionsAreFullWrites() {
        let rows: [(UInt8, UInt32, Mnemonic, String)] = [
            (0x9A, 0b100, .fcvt, "fcvt z0.h, p1/z, z1.s"),
            (0x9A, 0b101, .fcvt, "fcvt z0.s, p1/z, z1.h"),
            (0xDA, 0b100, .fcvt, "fcvt z0.h, p1/z, z1.d"),
            (0x1A, 0b110, .fcvtx, "fcvtx z0.s, p1/z, z1.d"),
            (0x9A, 0b110, .bfcvt, "bfcvt z0.h, p1/z, z1.s"),
            (0x58, 0b100, .frintn, "frintn z0.h, p1/z, z1.h"),
            (0x5C, 0b110, .scvtf, "scvtf z0.h, p1/z, z1.h"),
            (0x1E, 0b101, .flogb, "flogb z0.h, p1/z, z1.h"),
        ]
        for (key, low, mnemonic, expected) in rows {
            let d = decode(zeroing(key, low))
            #expect(d.mnemonic == mnemonic, "key 0x\(String(key, radix: 16)),\(low)")
            #expect(text(zeroing(key, low)) == expected)
            #expect(d.scalableEffect == .readsStreamingMode, "\(expected) is a full /z write")
            #expect(canonicalIndices(d.semanticReads) == [33], "\(expected) reads only the source")
        }
    }

    @Test func reservedZeroingFormKeysAreHoles() {
        // Both keys route to the zeroing decoder (bit20=bit19=1) and miss the
        // form table, so they exercise its reserved-slot rejection.
        #expect(decode(zeroing(0x18, 0b100)).mnemonic == .undefined)
        #expect(decode(zeroing(0x9A, 0b111)).mnemonic == .undefined, "fcvt has no 111 slot")
    }

    @Test func topHalfConvertsPreserveTheDestinationInBothQualifiers() {
        // FCVTNT/FCVTXNT/BFCVTNT read the destination and set partialWrite even
        // under /z (the ASL seeds the result from Zd).
        let converts: [(UInt8, Mnemonic, String, String)] = [
            (0x80, .fcvtnt, "fcvtnt z0.h, p1/m, z1.s", "fcvtnt z0.h, p1/z, z1.s"),
            (0x02, .fcvtxnt, "fcvtxnt z0.s, p1/m, z1.d", "fcvtxnt z0.s, p1/z, z1.d"),
            (0x82, .bfcvtnt, "bfcvtnt z0.h, p1/m, z1.s", "bfcvtnt z0.h, p1/z, z1.s"),
            (0xC2, .fcvtnt, "fcvtnt z0.s, p1/m, z1.d", "fcvtnt z0.s, p1/z, z1.d"),
        ]
        for (key, mnemonic, mergeText, zeroText) in converts {
            for merging in [true, false] {
                let d = decode(convertPrecision(key, merging: merging))
                #expect(d.mnemonic == mnemonic, "key 0x\(String(key, radix: 16))")
                #expect(text(convertPrecision(key, merging: merging)) == (merging ? mergeText : zeroText))
                #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "top-convert always preserves")
                #expect(canonicalIndices(d.semanticReads) == [32, 33], "the destination is always read")
            }
        }
    }

    @Test func fcvtltIsPartialOnlyWhenMerging() {
        let merge = decode(convertPrecision(0x81, merging: true))
        #expect(merge.mnemonic == .fcvtlt)
        #expect(text(convertPrecision(0x81, merging: true)) == "fcvtlt z0.s, p1/m, z1.h")
        #expect(merge.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(merge.semanticReads) == [32, 33])

        let zero = decode(convertPrecision(0x81, merging: false))
        #expect(text(convertPrecision(0x81, merging: false)) == "fcvtlt z0.s, p1/z, z1.h")
        #expect(zero.scalableEffect == .readsStreamingMode, "fcvtlt /z is a full write")
        #expect(canonicalIndices(zero.semanticReads) == [33], "fcvtlt /z reads only the source")
    }

    @Test func fcvtltDoubleFormAndConvertPrecisionHoles() {
        #expect(text(convertPrecision(0xC3, merging: true)) == "fcvtlt z0.d, p1/m, z1.s")
        // A form key with no convert-precision member is a hole.
        #expect(decode(convertPrecision(0x00, merging: true)).mnemonic == .undefined)
        #expect(decode(convertPrecision(0x40, merging: false)).mnemonic == .undefined)
    }
}

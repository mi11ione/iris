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

/// Validates the vector-permute cluster at top byte 0x05 (bits[15:13] classes):
/// the ZIP/UZP/TRN family in all three operand shapes (predicate, vector, and
/// the F64MM 128-bit quadword), EXT destructive and constructive, TBL/TBX and
/// the SVE2p1 TBXQ, the DUPQ/EXTQ within-segment forms, INSR from a GPR and a
/// SIMD scalar, the UNPK widening family, and the unpredicated REV. Element size
/// rides bits[23:22]; the reference text pins the register roles and suffixes.
@Suite("SVE permute / vector permute, table, unpack")
struct SVEVectorPermuteDecodeTests {
    private static let zipUzpTrn: [(UInt32, Mnemonic, String)] = [
        // predicate forms (bit20=0, Pd/Pn/Pm 4-bit)
        (0x0520_4000, .zip1, "zip1 p0.b, p0.b, p0.b"),
        (0x0520_4400, .zip2, "zip2 p0.b, p0.b, p0.b"),
        (0x0520_4800, .uzp1, "uzp1 p0.b, p0.b, p0.b"),
        (0x0520_4C00, .uzp2, "uzp2 p0.b, p0.b, p0.b"),
        (0x0520_5000, .trn1, "trn1 p0.b, p0.b, p0.b"),
        (0x0520_5400, .trn2, "trn2 p0.b, p0.b, p0.b"),
        // vector forms (bits[15:13]=011)
        (0x0520_6000, .zip1, "zip1 z0.b, z0.b, z0.b"),
        (0x0560_6000, .zip1, "zip1 z0.h, z0.h, z0.h"),
        (0x05A0_6000, .zip1, "zip1 z0.s, z0.s, z0.s"),
        (0x05E0_6000, .zip1, "zip1 z0.d, z0.d, z0.d"),
        (0x0520_6400, .zip2, "zip2 z0.b, z0.b, z0.b"),
        (0x0520_6800, .uzp1, "uzp1 z0.b, z0.b, z0.b"),
        (0x0520_7400, .trn2, "trn2 z0.b, z0.b, z0.b"),
        // F64MM 128-bit quadword forms (decodeExt 128-perm branch)
        (0x05A0_0000, .zip1, "zip1 z0.q, z0.q, z0.q"),
        (0x05A0_0400, .zip2, "zip2 z0.q, z0.q, z0.q"),
        (0x05A0_0800, .uzp1, "uzp1 z0.q, z0.q, z0.q"),
        (0x05A0_0C00, .uzp2, "uzp2 z0.q, z0.q, z0.q"),
        (0x05A0_1800, .trn1, "trn1 z0.q, z0.q, z0.q"),
        (0x05A0_1C00, .trn2, "trn2 z0.q, z0.q, z0.q"),
    ]

    @Test func everyZipUzpTrnFormDecodes() {
        for (encoding, mnemonic, expected) in Self.zipUzpTrn {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(decode(encoding).scalableEffect == .readsStreamingMode)
        }
    }

    private static let tableAndExtract: [(UInt32, Mnemonic, String)] = [
        (0x0520_0000, .ext, "ext z0.b, z0.b, z0.b, #0"), // destructive
        (0x0560_0000, .ext, "ext z0.b, { z0.b, z1.b }, #0"), // constructive (SVE2)
        (0x0520_3000, .tbl, "tbl z0.b, { z0.b }, z0.b"), // single-register table
        (0x0520_2800, .tbl, "tbl z0.b, { z0.b, z1.b }, z0.b"), // two-register table (SVE2)
        (0x05E0_2800, .tbl, "tbl z0.d, { z0.d, z1.d }, z0.d"),
        (0x0520_2C00, .tbx, "tbx z0.b, z0.b, z0.b"),
        (0x0520_3400, .tbxq, "tbxq z0.b, z0.b, z0.b"),
        (0x0521_2400, .dupq, "dupq z0.b, z0.b[0]"),
        (0x0522_2400, .dupq, "dupq z0.h, z0.h[0]"),
        (0x0524_2400, .dupq, "dupq z0.s, z0.s[0]"),
        (0x0528_2400, .dupq, "dupq z0.d, z0.d[0]"),
        (0x0560_2400, .extq, "extq z0.b, z0.b, z0.b, #0"),
    ]

    @Test func everyTableAndExtractFormDecodes() {
        for (encoding, mnemonic, expected) in Self.tableAndExtract {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    private static let insrAndUnpk: [(UInt32, Mnemonic, String)] = [
        (0x0524_3800, .insr, "insr z0.b, w0"), // from GPR (w)
        (0x05E4_3800, .insr, "insr z0.d, x0"), // from GPR (x)
        (0x0534_3800, .insr, "insr z0.b, b0"), // from SIMD scalar
        (0x05F4_3800, .insr, "insr z0.d, d0"),
        (0x0570_3800, .sunpklo, "sunpklo z0.h, z0.b"),
        (0x0571_3800, .sunpkhi, "sunpkhi z0.h, z0.b"),
        (0x0572_3800, .uunpklo, "uunpklo z0.h, z0.b"),
        (0x0573_3800, .uunpkhi, "uunpkhi z0.h, z0.b"),
        (0x05B3_3800, .uunpkhi, "uunpkhi z0.s, z0.h"),
        (0x05F3_3800, .uunpkhi, "uunpkhi z0.d, z0.s"),
        (0x0538_3800, .rev, "rev z0.b, z0.b"), // unpredicated vector reverse
        (0x05F8_3800, .rev, "rev z0.d, z0.d"),
    ]

    @Test func everyInsrUnpkRevFormDecodes() {
        for (encoding, mnemonic, expected) in Self.insrAndUnpk {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func insrFromGprReadsTheGprAndDestinationVector() {
        let d = decode(0x0524_3800) // insr z0.b, w0
        #expect(canonicalIndices(d.semanticReads) == [0, 32]) // W0 + Z0 (destructive)
        #expect(canonicalIndices(d.semanticWrites) == [32])
    }

    @Test func unpkSourceIsHalfTheDestinationElement() {
        // The reserved byte-destination (sz=00) unpack has no source half.
        #expect(decode(0x0530_3800).mnemonic == .undefined, "unpk with byte destination is reserved")
    }
}

/// Validates the predicated-permute cluster at 0x05 (bits[15:13]=010): the
/// predicate ZIP/UZP/TRN and the REV/PUNPK predicate manipulations, all of
/// which touch the predicate register file (scalable reads/writes) rather than
/// the Z bank, and carry no partial-write.
@Suite("SVE permute / predicate permute and unpack")
struct SVEPredicatePermuteDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x0520_4000, .zip1, "zip1 p0.b, p0.b, p0.b"),
        (0x0560_4000, .zip1, "zip1 p0.h, p0.h, p0.h"),
        (0x0534_4000, .rev, "rev p0.b, p0.b"), // predicate reverse
        (0x0574_4000, .rev, "rev p0.h, p0.h"),
        (0x0530_4000, .punpklo, "punpklo p0.h, p0.b"),
        (0x0531_4000, .punpkhi, "punpkhi p0.h, p0.b"),
    ]

    @Test func everyPredicatePermuteFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    @Test func predicatePermutesTouchOnlyThePredicateFile() {
        let zip = decode(0x0520_4000) // zip1 p0.b, p0.b, p0.b
        #expect(zip.semanticReads == .empty)
        #expect(zip.semanticWrites == .empty)
        #expect(zip.scalableReads.containsPredicate(0))
        #expect(zip.scalableWrites.containsPredicate(0))
        #expect(zip.scalableEffect == .readsStreamingMode)
    }
}

/// Validates the predicated unary/last cluster (bits[15:13]=100/101): COMPACT/
/// EXPAND, SPLICE (destructive + constructive), CLASTA/B and LASTA/B writing a
/// vector, a SIMD scalar, or a GPR, and the REVB/H/W/D reverse-within-element
/// family in both its predicated-merging (`/m`) and predicated-zeroing (`/z`)
/// halves. The merging forms are the only 2s.5 records with `partialWrite` (the
/// inactive destination lanes survive); the zeroing twins are full writes.
@Suite("SVE permute / predicated unary, splice, last, reverse")
struct SVEPredicatedUnaryDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x0521_8000, .compact, "compact z0.b, p0, z0.b"),
        (0x0531_8000, .expand, "expand z0.b, p0, z0.b"),
        (0x052C_8000, .splice, "splice z0.b, p0, z0.b, z0.b"), // destructive
        (0x052D_8000, .splice, "splice z0.b, p0, { z0.b, z1.b }"), // constructive
        (0x0522_8000, .lasta, "lasta b0, p0, z0.b"), // to SIMD scalar
        (0x0523_8000, .lastb, "lastb b0, p0, z0.b"),
        (0x0520_A000, .lasta, "lasta w0, p0, z0.b"), // to GPR
        (0x05E0_A000, .lasta, "lasta x0, p0, z0.d"),
        (0x0521_A000, .lastb, "lastb w0, p0, z0.b"),
        (0x0528_8000, .clasta, "clasta z0.b, p0, z0.b, z0.b"), // to vector
        (0x0529_8000, .clastb, "clastb z0.b, p0, z0.b, z0.b"),
        (0x052A_8000, .clasta, "clasta b0, p0, b0, z0.b"), // to SIMD scalar
        (0x0530_A000, .clasta, "clasta w0, p0, w0, z0.b"), // to GPR
        (0x0531_A000, .clastb, "clastb w0, p0, w0, z0.b"),
        (0x05F0_A000, .clasta, "clasta x0, p0, x0, z0.d"),
    ]

    @Test func everyPredicatedUnaryFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
        }
    }

    private static let reverseWithin: [(UInt32, Mnemonic, String, ScalableEffect)] = [
        (0x0564_8000, .revb, "revb z0.h, p0/m, z0.h", [.readsStreamingMode, .partialWrite]),
        (0x0564_A000, .revb, "revb z0.h, p0/z, z0.h", .readsStreamingMode),
        (0x05A5_8000, .revh, "revh z0.s, p0/m, z0.s", [.readsStreamingMode, .partialWrite]),
        (0x05A5_A000, .revh, "revh z0.s, p0/z, z0.s", .readsStreamingMode),
        (0x05E6_8000, .revw, "revw z0.d, p0/m, z0.d", [.readsStreamingMode, .partialWrite]),
        (0x052E_8000, .revd, "revd z0.q, p0/m, z0.q", [.readsStreamingMode, .partialWrite]),
        (0x052E_A000, .revd, "revd z0.q, p0/z, z0.q", .readsStreamingMode),
        (0x0527_8000, .rbit, "rbit z0.b, p0/m, z0.b", [.readsStreamingMode, .partialWrite]),
        (0x0527_A000, .rbit, "rbit z0.b, p0/z, z0.b", .readsStreamingMode),
    ]

    @Test func mergingReversesArePartialWritesAndZeroingReversesAreFull() {
        for (encoding, mnemonic, expected, effect) in Self.reverseWithin {
            let d = decode(encoding)
            #expect(d.mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(d.scalableEffect == effect, "\(expected) effect")
        }
    }

    @Test func mergingReverseReadsItsDestinationButZeroingDoesNot() {
        // `/m` preserves inactive lanes, so the destination is a semantic read;
        // `/z` discards them, so only the source is read. Distinct Zd/Zn make
        // the difference visible.
        let merging = decode(0x0564_8041) // revb z1.h, p0/m, z2.h
        #expect(canonicalIndices(merging.semanticReads) == [33, 34]) // Zd + Zn (RMW)
        let zeroing = decode(0x0564_A041) // revb z1.h, p0/z, z2.h
        #expect(canonicalIndices(zeroing.semanticReads) == [34]) // Zn only
    }

    @Test func revbBelowHalfwordIsReserved() {
        // REVB needs an element ≥ H; the byte form (sz=00) is a hole.
        #expect(decode(0x0524_8000).mnemonic == .undefined)
    }
}

/// Validates SEL and its `mov` alias, and PMOV in both directions. SEL with a
/// distinct third source is the general vector select; SEL with `Zm == Zd`
/// renders the `mov Zd.<T>, Pg/m, Zn.<T>` predicated-move alias and, like every
/// merging move, carries `partialWrite`. PMOV moves a predicate to/from a
/// vector, so exactly one of its two register banks is touched per direction.
@Suite("SVE permute / select, move alias, predicate-vector move")
struct SVESelectAndPmovDecodeTests {
    @Test func selectRendersWithABareGoverningPredicate() {
        let d = decode(0x0520_C001) // sel z1.b, p0, z0.b, z0.b
        #expect(d.mnemonic == .sel)
        #expect(text(0x0520_C001) == "sel z1.b, p0, z0.b, z0.b")
        #expect(d.scalableEffect == .readsStreamingMode)
        #expect(canonicalIndices(d.semanticWrites) == [33]) // Z1
    }

    @Test func selectWithMatchingSourceIsTheMergingMoveAlias() {
        let d = decode(0x0520_C000) // sel z0, p0, z0, z0 → mov z0.b, p0/m, z0.b
        #expect(d.mnemonic == .mov)
        #expect(text(0x0520_C000) == "mov z0.b, p0/m, z0.b")
        #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(canonicalIndices(d.semanticReads) == [32]) // destructive RMW
    }

    private static let pmov: [(UInt32, String, [Int], [Int])] = [
        // (encoding, text, semanticReads, semanticWrites) — one bank per direction
        (0x052A_3800, "pmov p0.b, z0", [32], []), // vector → predicate (no index)
        (0x052B_3800, "pmov z0, p0.b", [], [32]), // predicate → vector
        (0x052C_3800, "pmov p0.h, z0[0]", [32], []), // indexed forms carry [i]
        (0x052D_3800, "pmov z0[0], p0.h", [], [32]),
        (0x05A8_3800, "pmov p0.d, z0[0]", [32], []),
    ]

    @Test func everyPmovDirectionTouchesExactlyOneBank() {
        for (encoding, expected, reads, writes) in Self.pmov {
            let d = decode(encoding)
            #expect(d.mnemonic == .pmov, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(canonicalIndices(d.semanticReads) == reads)
            #expect(canonicalIndices(d.semanticWrites) == writes)
        }
        // The predicate side of PMOV rides the scalable register file.
        #expect(decode(0x052A_3800).scalableWrites.containsPredicate(0)) // Pd written
        #expect(decode(0x052B_3800).scalableReads.containsPredicate(0)) // Pn read
    }
}

/// Validates the SVE2p1 quadword-permute cluster at top byte 0x44 (TBLQ/UZPQ/
/// ZIPQ) — the within-128-bit-segment twins of the plain permutes. TBLQ takes a
/// single-register table list; UZPQ/ZIPQ are plain three-register forms. Element
/// size spans all four widths via bits[24:23].
@Suite("SVE permute / quadword permute cluster (0x44)")
struct SVEQuadwordPermuteDecodeTests {
    private static let rows: [(UInt32, Mnemonic, String)] = [
        (0x4400_F800, .tblq, "tblq z0.b, { z0.b }, z0.b"),
        (0x44C0_F800, .tblq, "tblq z0.d, { z0.d }, z0.d"),
        (0x4400_E000, .zipq1, "zipq1 z0.b, z0.b, z0.b"),
        (0x4400_E400, .zipq2, "zipq2 z0.b, z0.b, z0.b"),
        (0x4400_E800, .uzpq1, "uzpq1 z0.b, z0.b, z0.b"),
        (0x4400_EC00, .uzpq2, "uzpq2 z0.b, z0.b, z0.b"),
        (0x4440_E000, .zipq1, "zipq1 z0.h, z0.h, z0.h"),
        (0x4480_E000, .zipq1, "zipq1 z0.s, z0.s, z0.s"),
    ]

    @Test func everyQuadwordPermuteFormDecodes() {
        for (encoding, mnemonic, expected) in Self.rows {
            #expect(decode(encoding).mnemonic == mnemonic, "0x\(String(encoding, radix: 16))")
            #expect(text(encoding) == expected)
            #expect(decode(encoding).scalableEffect == .readsStreamingMode)
        }
    }

    @Test func quadwordReservedOpcodeIsUndefined() {
        // bits[12:10] ∈ {100, 101, 111} are reserved in the quadword cluster.
        #expect(decode(0x4400_F000).mnemonic == .undefined)
    }
}

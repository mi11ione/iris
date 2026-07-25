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

/// Every `mop4Base` row (M/N-stripped key → mnemonic).
private let mop4s: [(UInt32, Mnemonic)] = [
    (0x80C0_0008, .fmop4a),
    (0x80C0_0018, .fmop4s),
    (0xA0C0_0008, .smop4a),
    (0xA0C0_0018, .smop4s),
    (0xA0E0_0008, .sumop4a),
    (0xA0E0_0018, .sumop4s),
    (0xA1C0_0008, .usmop4a),
    (0xA1C0_0018, .usmop4s),
    (0xA1E0_0008, .umop4a),
    (0xA1E0_0018, .umop4s),
    (0x8020_0008, .fmop4a),
    (0x8100_0008, .fmop4a),
    (0x8100_0018, .fmop4s),
    (0x8120_0008, .bfmop4a),
    (0x8120_0018, .bfmop4s),
    (0x8000_0000, .fmop4a),
    (0x8000_0010, .fmop4s),
    (0x8000_8000, .smop4a),
    (0x8000_8008, .smop4a),
    (0x8000_8010, .smop4s),
    (0x8000_8018, .smop4s),
    (0x8020_0000, .fmop4a),
    (0x8020_8000, .sumop4a),
    (0x8020_8010, .sumop4s),
    (0x8100_0000, .bfmop4a),
    (0x8100_0010, .bfmop4s),
    (0x8100_8000, .usmop4a),
    (0x8100_8008, .umop4a),
    (0x8100_8010, .usmop4s),
    (0x8100_8018, .umop4s),
    (0x8120_0000, .fmop4a),
    (0x8120_0010, .fmop4s),
    (0x8120_8000, .umop4a),
    (0x8120_8010, .umop4s),
]

/// Every `decodeTmop` row (encoding → mnemonic).
private let tmops: [(UInt32, Mnemonic)] = [
    (0x8140_0008, .ftmopa),
    (0x8060_0008, .ftmopa),
    (0x8160_0008, .bftmopa),
    (0x8040_0000, .ftmopa),
    (0x8060_0000, .ftmopa),
    (0x8160_0000, .ftmopa),
    (0x8140_0000, .bftmopa),
    (0x8040_8000, .stmopa),
    (0x8040_8008, .stmopa),
    (0x8160_8000, .utmopa),
    (0x8140_8008, .utmopa),
    (0x8060_8000, .sutmopa),
    (0x8140_8000, .ustmopa),
]

/// Validates the SME2 outer-product-extension decoders: the MOP4 quarter-tile
/// products (all tiles, both bit23 halves), the TMOP sparse products, and the
/// predicated residues that share 2s.6's outer-product cells (the 2-way
/// I16->I32 integer products and the FP8 FMOPA). MOP4/TMOP are unpredicated with
/// restricted source lanes; the residues reuse 2s.6's predicated shape.
@Suite("SME2 / outer-product decode")
struct SME2OuterProductDecodeTests {
    @Test func everyMop4RowResolvesAndIsConsistent() {
        for (e, m) in mop4s {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
        }
    }

    @Test func everyTmopRowResolvesAndIsConsistent() {
        for (e, m) in tmops {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
        }
    }

    @Test func mop4RendersItsRestrictedSourceLanes() {
        // Zn is 2*field (z0-z14 even), Zm is 2*field+16 (z16-z30 even); the pair
        // forms (M/N bits) widen a source to a group.
        #expect(text(0x80C0_0008) == "fmop4a za0.d, z0.d, z16.d")
        #expect(text(0x8000_0000) == "fmop4a za0.s, z0.s, z16.s")
        // N (bit9) makes Zn a pair, M (bit20) makes Zm a pair.
        #expect(text(0x8000_0200) == "fmop4a za0.s, { z0.s, z1.s }, z16.s")
        #expect(text(0x8010_0000) == "fmop4a za0.s, z0.s, { z16.s, z17.s }")
    }

    @Test func tmopRendersItsSparseIndexedSource() {
        #expect(text(0x8140_0008) == "ftmopa za0.h, { z0.h, z1.h }, z0.h, z20[0]")
        #expect(text(0x8040_0000) == "ftmopa za0.s, { z0.s, z1.s }, z0.s, z20[0]")
    }

    @Test func theTmopSparsityIndexRegisterBaseFollowsBit12() {
        // The Zk sparsity-index register has base z20 (bit12=0) or z28 (bit12=1).
        #expect(text(0x8140_0008).contains("z20["))
        #expect(text(0x8140_1008) == "ftmopa za0.h, { z0.h, z1.h }, z0.h, z28[0]")
        #expect(decode(0x8140_1008).mnemonic == .ftmopa)
    }

    @Test func theResiduesReuseThePredicatedOuterProductShape() {
        // The 2-way I16->I32 SMOPA/UMOPA/SMOPS/UMOPS and the FP8 FMOPA (.s and .h
        // tiles) share bit23=1 with 2s.6's outer products.
        let residues: [(UInt32, Mnemonic)] = [
            (0xA080_0008, .smopa), (0xA080_0018, .smops),
            (0xA180_0008, .umopa), (0xA180_0018, .umops),
        ]
        for (e, m) in residues {
            let d = decode(e)
            #expect(d.mnemonic == m, "0x\(String(e, radix: 16))")
            let t = text(e)
            #expect(!t.isEmpty && !t.contains("?"), "0x\(String(e, radix: 16)) -> \(t)")
        }
        #expect(text(0xA080_0008) == "smopa za0.s, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x80A0_0000) == "fmopa za0.s, p0/m, p0/m, z0.b, z0.b")
        #expect(text(0x80A0_0008) == "fmopa za0.h, p0/m, p0/m, z0.b, z0.b")
    }

    @Test func everyOuterProductReadsAndWritesItsTileUnderStreaming() {
        for (e, _) in mop4s + tmops {
            let d = decode(e)
            #expect(!d.scalableReads.zaMask.isEmpty, "0x\(String(e, radix: 16))")
            #expect(!d.scalableWrites.zaMask.isEmpty, "0x\(String(e, radix: 16))")
            #expect(d.scalableEffect == [.readsStreamingMode, .partialWrite], "0x\(String(e, radix: 16))")
        }
    }
}

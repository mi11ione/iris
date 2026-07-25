// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0, features: .scalable)
}

private func text(_ encoding: UInt32) -> String {
    decode(encoding).text
}

/// One row of the outer-product machine table: the all-fields-zero encoding,
/// the mnemonic it must resolve to, and the `ZA` tile / `Z` source element
/// suffixes (which differ for every widening, I8→I32 and I16→I64 form).
private struct OuterProductCase {
    let encoding: UInt32
    let mnemonic: Mnemonic
    let name: String
    let tile: String
    let source: String
}

/// The complete 2s.6 outer-product cube — all thirty core rows across the four
/// encoding cells, ordered by tile element then by encoding value.
private let outerProducts: [OuterProductCase] = [
    // `.s` tiles: ZAda = bits[1:0].
    OuterProductCase(encoding: 0x8080_0000, mnemonic: .fmopa, name: "fmopa", tile: "s", source: "s"),
    OuterProductCase(encoding: 0x8080_0010, mnemonic: .fmops, name: "fmops", tile: "s", source: "s"),
    OuterProductCase(encoding: 0x8080_0008, mnemonic: .bmopa, name: "bmopa", tile: "s", source: "s"),
    OuterProductCase(encoding: 0x8080_0018, mnemonic: .bmops, name: "bmops", tile: "s", source: "s"),
    OuterProductCase(encoding: 0x8180_0000, mnemonic: .bfmopa, name: "bfmopa", tile: "s", source: "h"),
    OuterProductCase(encoding: 0x8180_0010, mnemonic: .bfmops, name: "bfmops", tile: "s", source: "h"),
    OuterProductCase(encoding: 0x81A0_0000, mnemonic: .fmopa, name: "fmopa", tile: "s", source: "h"),
    OuterProductCase(encoding: 0x81A0_0010, mnemonic: .fmops, name: "fmops", tile: "s", source: "h"),
    OuterProductCase(encoding: 0xA080_0000, mnemonic: .smopa, name: "smopa", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA080_0010, mnemonic: .smops, name: "smops", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA0A0_0000, mnemonic: .sumopa, name: "sumopa", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA0A0_0010, mnemonic: .sumops, name: "sumops", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA180_0000, mnemonic: .usmopa, name: "usmopa", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA180_0010, mnemonic: .usmops, name: "usmops", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA1A0_0000, mnemonic: .umopa, name: "umopa", tile: "s", source: "b"),
    OuterProductCase(encoding: 0xA1A0_0010, mnemonic: .umops, name: "umops", tile: "s", source: "b"),
    // `.d` tiles: ZAda = bits[2:0].
    OuterProductCase(encoding: 0x80C0_0000, mnemonic: .fmopa, name: "fmopa", tile: "d", source: "d"),
    OuterProductCase(encoding: 0x80C0_0010, mnemonic: .fmops, name: "fmops", tile: "d", source: "d"),
    OuterProductCase(encoding: 0xA0C0_0000, mnemonic: .smopa, name: "smopa", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA0C0_0010, mnemonic: .smops, name: "smops", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA0E0_0000, mnemonic: .sumopa, name: "sumopa", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA0E0_0010, mnemonic: .sumops, name: "sumops", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA1C0_0000, mnemonic: .usmopa, name: "usmopa", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA1C0_0010, mnemonic: .usmops, name: "usmops", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA1E0_0000, mnemonic: .umopa, name: "umopa", tile: "d", source: "h"),
    OuterProductCase(encoding: 0xA1E0_0010, mnemonic: .umops, name: "umops", tile: "d", source: "h"),
    // `.h` tiles: ZAda = bit0 (the host-absent F16F16 / B16B16 quartet).
    OuterProductCase(encoding: 0x8180_0008, mnemonic: .fmopa, name: "fmopa", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x8180_0018, mnemonic: .fmops, name: "fmops", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x81A0_0008, mnemonic: .bfmopa, name: "bfmopa", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x81A0_0018, mnemonic: .bfmops, name: "bfmops", tile: "h", source: "h"),
]

/// A populated register/predicate payload: Zm=9, Pm=5, Pn=2, Zn=7. Every field
/// sits outside the mask of every row, so it applies uniformly to the cube.
private let payload: UInt32 = (9 << 16) | (5 << 13) | (2 << 10) | (7 << 5)

/// Validates the SME outer-product decoder — the FMOPA/FMOPS, BFMOPA/BFMOPS,
/// signed/unsigned/mixed integer MOPA/MOPS, and BMOPA/BMOPS family that
/// accumulates (or subtracts) the outer product of two `Z` vectors into a `ZA`
/// tile. The cube is the widest data-type surface in 2s.6: thirty rows whose
/// mnemonic, tile element and source element are all encoded in scattered
/// selector bits (the bit24 region, bit21, bit22, bit23, bit3, bit4), including
/// the 16-bit chiasmus where a single bit swaps FMOPA-widening for the
/// non-widening F16F16 form. Every row is asserted individually because a
/// mis-transcribed selector silently produces a plausible-looking wrong
/// instruction rather than a hole.
@Suite("SME core / outer-product decode")
struct SMEOuterProductDecodeTests {
    @Test func everyRowResolvesToItsMnemonicAndElementSuffixes() {
        for row in outerProducts {
            let draft = decode(row.encoding)
            #expect(draft.mnemonic == row.mnemonic, "0x\(String(row.encoding, radix: 16))")
            #expect(draft.category == .sme)
            #expect(
                text(row.encoding) == "\(row.name) za0.\(row.tile), p0/m, p0/m, z0.\(row.source), z0.\(row.source)",
                "0x\(String(row.encoding, radix: 16))",
            )
        }
    }

    @Test func everyRowCarriesItsRegisterAndPredicateFields() {
        // Pn is bits[12:10] and renders first; Pm is bits[15:13] and renders
        // second — an order the encoding does not suggest.
        for row in outerProducts {
            let encoding = row.encoding | payload
            let tileIndex = row.tile == "s" ? 3 : (row.tile == "d" ? 5 : 1)
            let expected = "\(row.name) za\(tileIndex).\(row.tile), p2/m, p5/m, z7.\(row.source), z9.\(row.source)"
            #expect(text(encoding | UInt32(tileIndex)) == expected, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theTileIndexFieldWidthFollowsTheTileElement() {
        // `.s` tiles are ZA0-3 (bits[1:0]), `.d` tiles ZA0-7 (bits[2:0]), `.h`
        // tiles ZA0-1 (bit0). The bits above each field are reserved, so a
        // too-wide read would name a nonexistent tile and a too-narrow one
        // would decode a hole.
        for zada in UInt32(0) ... 3 {
            #expect(text(0x8080_0000 | zada) == "fmopa za\(zada).s, p0/m, p0/m, z0.s, z0.s")
        }
        for zada in UInt32(0) ... 7 {
            #expect(text(0x80C0_0000 | zada) == "fmopa za\(zada).d, p0/m, p0/m, z0.d, z0.d")
        }
        for zada in UInt32(0) ... 1 {
            #expect(text(0x8180_0008 | zada) == "fmopa za\(zada).h, p0/m, p0/m, z0.h, z0.h")
        }
    }

    @Test func theSixteenBitQuartetIsAChiasmusOnBitTwentyOneAndBitThree() {
        // The four 16-bit-input rows swap identity on (bit21, bit3): the
        // widening form and the non-widening form of the *other* float type
        // share each frame. A transposition here would be invisible in the
        // mnemonic alone, so the tile suffix pins it.
        #expect(text(0x8180_0000) == "bfmopa za0.s, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x8180_0008) == "fmopa za0.h, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x81A0_0000) == "fmopa za0.s, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x81A0_0008) == "bfmopa za0.h, p0/m, p0/m, z0.h, z0.h")
    }

    @Test func theBinaryOuterProductSitsInsideTheFloatFrame() {
        // BMOPA/BMOPS occupy bit3=1 of the F32 frame — an in-frame split, not
        // residue, so they must decode rather than fall through.
        #expect(text(0x8080_0008) == "bmopa za0.s, p0/m, p0/m, z0.s, z0.s")
        #expect(text(0x8080_0018) == "bmops za0.s, p0/m, p0/m, z0.s, z0.s")
    }

    @Test func theSBitSelectsAccumulateVersusSubtract() {
        // Bit4 is the only difference between every OPA and its OPS twin.
        for row in outerProducts where row.name.hasSuffix("opa") {
            let subtract = decode(row.encoding | 0x10)
            #expect(subtract.mnemonic != row.mnemonic, "0x\(String(row.encoding, radix: 16))")
        }
    }

    @Test func theExtremeRegisterAndPredicateIndicesRender() {
        // Zn/Zm are 5-bit (z0-z31); the governing predicates are 3-bit (p0-p7),
        // so p8-p15 must be unreachable by construction.
        let maxed: UInt32 = 0x8080_0000 | (31 << 16) | (7 << 13) | (7 << 10) | (31 << 5) | 3
        #expect(text(maxed) == "fmopa za3.s, p7/m, p7/m, z31.s, z31.s")
    }
}

/// Validates the semantic attributes the outer-product records carry — the
/// accumulate model (`ZAda` is read *and* written), the `Z` source reads, the
/// governing-predicate reads, and the streaming/partial-write effect flags.
/// These never appear in the rendered text, so only a direct assertion catches
/// a record that disassembles perfectly but would mislead dataflow analysis.
@Suite("SME core / outer-product semantics")
struct SMEOuterProductSemanticsTests {
    @Test func theAccumulatorTileIsBothReadAndWritten() {
        // An outer product is a read-modify-write of its ZA tile: the same
        // residue mask must appear on both sides.
        for row in outerProducts {
            let draft = decode(row.encoding)
            let element: ScalarSize = row.tile == "s" ? .s : (row.tile == "d" ? .d : .h)
            let expected = ZATileMask(tile: 0, element: element)
            #expect(draft.scalableReads.zaMask == expected, "0x\(String(row.encoding, radix: 16))")
            #expect(draft.scalableWrites.zaMask == expected, "0x\(String(row.encoding, radix: 16))")
        }
    }

    @Test func theTileMaskTracksTheEncodedTileIndex() {
        // ZA tiles overlap: ZA0.D and ZA2.D share no rows, but ZA0.S and ZA0.D
        // do. The residue mask is the currency for that, so it must follow the
        // decoded tile index rather than being pinned to tile 0.
        for zada in UInt32(0) ... 7 {
            let draft = decode(0x80C0_0000 | zada)
            #expect(draft.scalableWrites.zaMask == ZATileMask(tile: UInt8(zada), element: .d))
        }
    }

    @Test func bothSourceVectorsAreSemanticReads() {
        let draft = decode(0x8080_0000 | (9 << 16) | (7 << 5))
        #expect(draft.semanticReads.contains(RegisterRef.simd(7)))
        #expect(draft.semanticReads.contains(RegisterRef.simd(9)))
        #expect(draft.semanticReads.count == 2)
        #expect(draft.semanticWrites.isEmpty)
    }

    @Test func bothGoverningPredicatesAreScalableReads() {
        let draft = decode(0x8080_0000 | (5 << 13) | (2 << 10))
        #expect(draft.scalableReads.containsPredicate(2))
        #expect(draft.scalableReads.containsPredicate(5))
        #expect(draft.scalableReads.predicateMask == (1 << 2) | (1 << 5))
        #expect(draft.scalableWrites.predicateMask == 0)
    }

    @Test func everyRowIsStreamingGatedAndPartial() {
        // All outer products require streaming mode plus ZA, and the predicated
        // accumulate leaves inactive elements intact.
        for row in outerProducts {
            let draft = decode(row.encoding)
            #expect(draft.scalableEffect == [.readsStreamingMode, .partialWrite],
                    "0x\(String(row.encoding, radix: 16))")
            #expect(draft.memoryAccess == .none)
            #expect(draft.flagEffect == .none)
            #expect(draft.branchClass == .none)
            #expect(draft.memoryOrdering == [])
        }
    }

    @Test func noOuterProductTouchesFFROrZT0() {
        for row in outerProducts {
            let draft = decode(row.encoding | payload)
            #expect(!draft.scalableReads.containsFFR, "0x\(String(row.encoding, radix: 16))")
            #expect(!draft.scalableWrites.containsFFR)
            #expect(!draft.scalableReads.containsZT0)
            #expect(!draft.scalableWrites.containsZT0)
        }
    }
}

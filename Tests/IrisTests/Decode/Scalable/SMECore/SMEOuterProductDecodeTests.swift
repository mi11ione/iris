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

private struct OuterProductCase {
    let encoding: UInt32
    let mnemonic: Mnemonic
    let name: String
    let tile: String
    let source: String
}

private let outerProducts: [OuterProductCase] = [
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
    OuterProductCase(encoding: 0x8180_0008, mnemonic: .fmopa, name: "fmopa", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x8180_0018, mnemonic: .fmops, name: "fmops", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x81A0_0008, mnemonic: .bfmopa, name: "bfmopa", tile: "h", source: "h"),
    OuterProductCase(encoding: 0x81A0_0018, mnemonic: .bfmops, name: "bfmops", tile: "h", source: "h"),
]

private let payload: UInt32 = (9 << 16) | (5 << 13) | (2 << 10) | (7 << 5)

/// Validates the SME outer-product decoder.
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
        for row in outerProducts {
            let encoding = row.encoding | payload
            let tileIndex = row.tile == "s" ? 3 : (row.tile == "d" ? 5 : 1)
            let expected = "\(row.name) za\(tileIndex).\(row.tile), p2/m, p5/m, z7.\(row.source), z9.\(row.source)"
            #expect(text(encoding | UInt32(tileIndex)) == expected, "0x\(String(encoding, radix: 16))")
        }
    }

    @Test func theTileIndexFieldWidthFollowsTheTileElement() {
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
        #expect(text(0x8180_0000) == "bfmopa za0.s, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x8180_0008) == "fmopa za0.h, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x81A0_0000) == "fmopa za0.s, p0/m, p0/m, z0.h, z0.h")
        #expect(text(0x81A0_0008) == "bfmopa za0.h, p0/m, p0/m, z0.h, z0.h")
    }

    @Test func theBinaryOuterProductSitsInsideTheFloatFrame() {
        #expect(text(0x8080_0008) == "bmopa za0.s, p0/m, p0/m, z0.s, z0.s")
        #expect(text(0x8080_0018) == "bmops za0.s, p0/m, p0/m, z0.s, z0.s")
    }

    @Test func theSBitSelectsAccumulateVersusSubtract() {
        for row in outerProducts where row.name.hasSuffix("opa") {
            let subtract = decode(row.encoding | 0x10)
            #expect(subtract.mnemonic != row.mnemonic, "0x\(String(row.encoding, radix: 16))")
        }
    }

    @Test func theExtremeRegisterAndPredicateIndicesRender() {
        let maxed: UInt32 = 0x8080_0000 | (31 << 16) | (7 << 13) | (7 << 10) | (31 << 5) | 3
        #expect(text(maxed) == "fmopa za3.s, p7/m, p7/m, z31.s, z31.s")
    }
}

/// Validates the semantic attributes the outer-product records carry.
@Suite("SME core / outer-product semantics")
struct SMEOuterProductSemanticsTests {
    @Test func theAccumulatorTileIsBothReadAndWritten() {
        for row in outerProducts {
            let draft = decode(row.encoding)
            let element: ScalarSize = row.tile == "s" ? .s : (row.tile == "d" ? .d : .h)
            let expected = ZATileMask(tile: 0, element: element)
            #expect(draft.scalableReads.zaMask == expected, "0x\(String(row.encoding, radix: 16))")
            #expect(draft.scalableWrites.zaMask == expected, "0x\(String(row.encoding, radix: 16))")
        }
    }

    @Test func theTileMaskTracksTheEncodedTileIndex() {
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

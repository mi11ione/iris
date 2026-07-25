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

/// The five MOVA blocks, in element order. `insert` moves a `Z` vector into a
/// tile slice; `extract` moves a tile slice into a `Z` vector.
private let movaBlocks: [(element: String, insert: UInt32, extract: UInt32)] = [
    ("b", 0xC000_0000, 0xC002_0000),
    ("h", 0xC040_0000, 0xC042_0000),
    ("s", 0xC080_0000, 0xC082_0000),
    ("d", 0xC0C0_0000, 0xC0C2_0000),
    ("q", 0xC0C1_0000, 0xC0C3_0000),
]

/// The tile|offset nibble split per element size, transcribed from the ARM
/// encoding diagrams: the tile field grows and the offset field shrinks as the
/// element narrows, and `.q` has no offset bits at all.
private struct NibbleSplit {
    let nibble: UInt32
    let b: (tile: UInt8, offset: UInt8)
    let h: (tile: UInt8, offset: UInt8)
    let s: (tile: UInt8, offset: UInt8)
    let d: (tile: UInt8, offset: UInt8)
    let q: (tile: UInt8, offset: UInt8)
}

private let nibbleSplits: [NibbleSplit] = [
    NibbleSplit(nibble: 0, b: (0, 0), h: (0, 0), s: (0, 0), d: (0, 0), q: (0, 0)),
    NibbleSplit(nibble: 1, b: (0, 1), h: (0, 1), s: (0, 1), d: (0, 1), q: (1, 0)),
    NibbleSplit(nibble: 2, b: (0, 2), h: (0, 2), s: (0, 2), d: (1, 0), q: (2, 0)),
    NibbleSplit(nibble: 3, b: (0, 3), h: (0, 3), s: (0, 3), d: (1, 1), q: (3, 0)),
    NibbleSplit(nibble: 4, b: (0, 4), h: (0, 4), s: (1, 0), d: (2, 0), q: (4, 0)),
    NibbleSplit(nibble: 5, b: (0, 5), h: (0, 5), s: (1, 1), d: (2, 1), q: (5, 0)),
    NibbleSplit(nibble: 6, b: (0, 6), h: (0, 6), s: (1, 2), d: (3, 0), q: (6, 0)),
    NibbleSplit(nibble: 7, b: (0, 7), h: (0, 7), s: (1, 3), d: (3, 1), q: (7, 0)),
    NibbleSplit(nibble: 8, b: (0, 8), h: (1, 0), s: (2, 0), d: (4, 0), q: (8, 0)),
    NibbleSplit(nibble: 9, b: (0, 9), h: (1, 1), s: (2, 1), d: (4, 1), q: (9, 0)),
    NibbleSplit(nibble: 10, b: (0, 10), h: (1, 2), s: (2, 2), d: (5, 0), q: (10, 0)),
    NibbleSplit(nibble: 11, b: (0, 11), h: (1, 3), s: (2, 3), d: (5, 1), q: (11, 0)),
    NibbleSplit(nibble: 12, b: (0, 12), h: (1, 4), s: (3, 0), d: (6, 0), q: (12, 0)),
    NibbleSplit(nibble: 13, b: (0, 13), h: (1, 5), s: (3, 1), d: (6, 1), q: (13, 0)),
    NibbleSplit(nibble: 14, b: (0, 14), h: (1, 6), s: (3, 2), d: (7, 0), q: (14, 0)),
    NibbleSplit(nibble: 15, b: (0, 15), h: (1, 7), s: (3, 3), d: (7, 1), q: (15, 0)),
]

private func split(_ row: NibbleSplit, _ element: String) -> (tile: UInt8, offset: UInt8) {
    switch element {
    case "b": row.b
    case "h": row.h
    case "s": row.s
    case "d": row.d
    default: row.q
    }
}

/// Validates the MOVA decoder — the tile↔vector move that ARM specifies is
/// *unconditionally* rendered as its `MOV` alias in both directions. The two
/// directions share a cell with a dense SME2 population, so each is claimed at
/// exact block granularity: the insert form must not swallow the multi-vector
/// MOVA, and the extract form must not swallow MOVAZ, which is the very same
/// word with bit9 set. The tile|offset nibble is the load-bearing field — one
/// 4-bit slot encodes both the tile number and the slice offset, split
/// differently at each of the five element sizes.
@Suite("SME core / MOVA decode")
struct SMEMovaDecodeTests {
    @Test func everyInsertBlockRendersTheAliasedMovIntoATileSlice() {
        for block in movaBlocks {
            let draft = decode(block.insert)
            #expect(draft.mnemonic == .mov, "insert .\(block.element)")
            #expect(draft.category == .sme)
            #expect(
                text(block.insert) == "mov za0h.\(block.element)[w12, 0], p0/m, z0.\(block.element)",
                "insert .\(block.element)",
            )
        }
    }

    @Test func everyExtractBlockRendersTheAliasedMovIntoAVector() {
        for block in movaBlocks {
            let draft = decode(block.extract)
            #expect(draft.mnemonic == .mov, "extract .\(block.element)")
            #expect(
                text(block.extract) == "mov z0.\(block.element), p0/m, za0h.\(block.element)[w12, 0]",
                "extract .\(block.element)",
            )
        }
    }

    @Test func theVerticalBitFlipsTheDirectionLetterInBothDirections() {
        // Bit15 selects a vertical slice; the letter sits between the tile
        // digit and the element suffix, never after it.
        for block in movaBlocks {
            #expect(
                text(block.insert | 0x8000) == "mov za0v.\(block.element)[w12, 0], p0/m, z0.\(block.element)",
                "insert .\(block.element)",
            )
            #expect(
                text(block.extract | 0x8000) == "mov z0.\(block.element), p0/m, za0v.\(block.element)[w12, 0]",
                "extract .\(block.element)",
            )
        }
    }

    @Test func theTileOffsetNibbleSplitsPerElementSizeOnInsert() {
        // The insert form carries the nibble at bits[3:0].
        for block in movaBlocks {
            for row in nibbleSplits {
                let (tile, offset) = split(row, block.element)
                let encoding = block.insert | row.nibble
                #expect(
                    text(encoding) == "mov za\(tile)h.\(block.element)[w12, \(offset)], p0/m, z0.\(block.element)",
                    "insert .\(block.element) nibble \(row.nibble)",
                )
            }
        }
    }

    @Test func theTileOffsetNibbleSplitsPerElementSizeOnExtract() {
        // The extract form carries the same nibble at bits[8:5].
        for block in movaBlocks {
            for row in nibbleSplits {
                let (tile, offset) = split(row, block.element)
                let encoding = block.extract | (row.nibble << 5)
                #expect(
                    text(encoding) == "mov z0.\(block.element), p0/m, za\(tile)h.\(block.element)[w12, \(offset)]",
                    "extract .\(block.element) nibble \(row.nibble)",
                )
            }
        }
    }

    @Test func theQuadwordFormAlwaysPrintsAZeroOffset() {
        // `.q` slices have no offset bits, but llvm-mc still prints the
        // mandatory `, 0` — a suppressed zero would diverge from the oracle.
        for tile in UInt32(0) ... 15 {
            #expect(text(0xC0C1_0000 | tile) == "mov za\(tile)h.q[w12, 0], p0/m, z0.q")
            #expect(text(0xC0C3_0000 | (tile << 5)) == "mov z0.q, p0/m, za\(tile)h.q[w12, 0]")
        }
    }

    @Test func theSelectRegisterIsW12PlusRv() {
        // The 2-bit Rv field names W12-W15 and nothing else.
        for rv in UInt32(0) ... 3 {
            #expect(text(0xC000_0000 | (rv << 13)) == "mov za0h.b[w\(12 + rv), 0], p0/m, z0.b")
            #expect(text(0xC002_0000 | (rv << 13)) == "mov z0.b, p0/m, za0h.b[w\(12 + rv), 0]")
        }
    }

    @Test func theGoverningPredicateIsMergingAndThreeBitsWide() {
        for pg in UInt32(0) ... 7 {
            #expect(text(0xC000_0000 | (pg << 10)) == "mov za0h.b[w12, 0], p\(pg)/m, z0.b")
            #expect(text(0xC002_0000 | (pg << 10)) == "mov z0.b, p\(pg)/m, za0h.b[w12, 0]")
        }
    }

    @Test func theVectorRegisterFieldsSpanTheWholeFile() {
        for z in UInt32(0) ... 31 {
            #expect(text(0xC000_0000 | (z << 5)) == "mov za0h.b[w12, 0], p0/m, z\(z).b")
            #expect(text(0xC002_0000 | z) == "mov z\(z).b, p0/m, za0h.b[w12, 0]")
        }
    }

    @Test func theMovazTwinDecodesAsItsOwnMnemonicNotAsAnExtract() {
        // MOVAZ is a core extract word plus bit9. Claiming it would render a
        // zeroing move as a merging one — the same text, different semantics.
        for block in movaBlocks {
            let movaz = block.extract | 0x0200
            #expect(decode(movaz).mnemonic == .movaz, "movaz .\(block.element)")
        }
    }
}

/// Validates the semantic attributes of the MOVA records. The two directions
/// are asymmetric in a way the text does not show: an insert reads *and* writes
/// its tile (the merging predicate preserves inactive elements), while an
/// extract reads the tile and partially writes the `Z` destination. Both read
/// the select GPR `Wv`, which appears in the text only as a register name
/// inside the slice brackets.
@Suite("SME core / MOVA semantics")
struct SMEMovaSemanticsTests {
    @Test func anInsertReadsAndWritesTheWholeDestinationTile() {
        // The slice index is dynamic, so the touched storage is the whole tile
        // — a sound over-approximation, not the single addressed slice.
        let draft = decode(0xC080_0000 | 0x4) // tile ZA1.S
        let tile = ZATileMask(tile: 1, element: .s)
        #expect(draft.scalableReads.zaMask == tile)
        #expect(draft.scalableWrites.zaMask == tile)
        #expect(draft.scalableEffect == [.readsStreamingMode, .partialWrite])
        #expect(draft.memoryAccess == .none)
    }

    @Test func anExtractReadsTheTileAndPartiallyWritesTheVector() {
        let draft = decode(0xC082_0000 | (0x4 << 5) | 7) // z7 ← ZA1.S slice
        #expect(draft.scalableReads.zaMask == ZATileMask(tile: 1, element: .s))
        #expect(draft.scalableWrites.zaMask == .none)
        #expect(draft.semanticWrites.contains(RegisterRef.simd(7)))
        // The merging qualifier makes the destination read-modify-write.
        #expect(draft.semanticReads.contains(RegisterRef.simd(7)))
        #expect(draft.scalableEffect == [.readsStreamingMode, .partialWrite])
    }

    @Test func theByteTileTouchesTheWholeArray() {
        // ZA0.B is the single byte tile; by the residue model it covers every
        // position, so a `.b` move overlaps every other tile.
        let draft = decode(0xC000_0000)
        #expect(draft.scalableWrites.zaMask == .whole)
        #expect(draft.scalableReads.zaMask == .whole)
    }

    @Test func theSelectRegisterIsASemanticGprRead() {
        for rv in UInt32(0) ... 3 {
            let insert = decode(0xC000_0000 | (rv << 13))
            #expect(insert.semanticReads.contains(RegisterRef.w(UInt8(12 + rv))))
            let extract = decode(0xC002_0000 | (rv << 13))
            #expect(extract.semanticReads.contains(RegisterRef.w(UInt8(12 + rv))))
        }
    }

    @Test func theSourceVectorOfAnInsertIsASemanticRead() {
        let draft = decode(0xC000_0000 | (19 << 5))
        #expect(draft.semanticReads.contains(RegisterRef.simd(19)))
        #expect(draft.semanticWrites.isEmpty)
    }

    @Test func theGoverningPredicateIsAScalableRead() {
        for pg in UInt32(0) ... 7 {
            #expect(decode(0xC000_0000 | (pg << 10)).scalableReads.containsPredicate(UInt8(pg)))
            #expect(decode(0xC002_0000 | (pg << 10)).scalableReads.containsPredicate(UInt8(pg)))
        }
    }
}

/// Validates the ZERO decoder — the one exact-mask producer in 2s.6. Its 8-bit
/// operand selects `ZA` tiles at `.d` granularity, but llvm-mc renders the
/// shortest uniform tile list that covers the same storage, which means an
/// alias table (`{}`, `{za}`, the two `.h` forms, twelve `.s` forms) sitting on
/// top of the generic `.d` decomposition, plus a comma-spacing quirk that
/// differs between the alias lists and the generic one. The whole 256-value
/// space is swept because every value is a distinct rendering decision.
@Suite("SME core / ZERO decode")
struct SMEZeroDecodeTests {
    /// The `.s` alias tile bit patterns: `za0.s` = 0x11 … `za3.s` = 0x88.
    private static func expectedText(_ imm8: UInt8) -> String {
        if imm8 == 0 { return "zero {}" }
        if imm8 == 0xFF { return "zero {za}" }
        if imm8 == 0x55 { return "zero {za0.h}" }
        if imm8 == 0xAA { return "zero {za1.h}" }
        if (imm8 >> 4) == (imm8 & 0xF) {
            let tiles = (UInt8(0) ..< 4).filter { ((imm8 & 0xF) >> $0) & 1 == 1 }.map { "za\($0).s" }
            return "zero {" + tiles.joined(separator: ",") + "}"
        }
        let tiles = (UInt8(0) ..< 8).filter { (imm8 >> $0) & 1 == 1 }.map { "za\($0).d" }
        return "zero {" + tiles.joined(separator: ", ") + "}"
    }

    @Test func everyMaskRendersItsShortestUniformTileList() {
        for imm8 in UInt32(0) ... 255 {
            #expect(text(0xC008_0000 | imm8) == Self.expectedText(UInt8(imm8)), "imm8 \(imm8)")
        }
    }

    @Test func theNamedAliasesRenderExactly() {
        #expect(text(0xC008_0000) == "zero {}")
        #expect(text(0xC008_00FF) == "zero {za}")
        #expect(text(0xC008_0055) == "zero {za0.h}")
        #expect(text(0xC008_00AA) == "zero {za1.h}")
        // The `.s` alias lists are comma-*no*-space; the generic `.d` lists
        // are comma-space. The difference is an llvm InstAlias-string artifact
        // the oracle text carries verbatim.
        #expect(text(0xC008_0011) == "zero {za0.s}")
        #expect(text(0xC008_0033) == "zero {za0.s,za1.s}")
        #expect(text(0xC008_00EE) == "zero {za1.s,za2.s,za3.s}")
        #expect(text(0xC008_0003) == "zero {za0.d, za1.d}")
        #expect(text(0xC008_00A5) == "zero {za0.d, za2.d, za5.d, za7.d}")
    }

    @Test func theWriteMaskIsTheExactReplicatedImmediate() {
        // ZERO is the only 2s.6 producer whose destination state is statically
        // known, so the write is exact and never `.partialWrite`.
        for imm8 in UInt32(0) ... 255 {
            let draft = decode(0xC008_0000 | imm8)
            let expected = ZATileMask(bits: UInt16(imm8) | (UInt16(imm8) << 8))
            #expect(draft.scalableWrites.zaMask == expected, "imm8 \(imm8)")
            #expect(draft.scalableReads == .empty, "imm8 \(imm8)")
        }
    }

    @Test func theWriteMaskAgreesWithTheRenderedTileList() {
        // The operand list and the residue mask are two derivations of the same
        // immediate; they must cover identical storage.
        for imm8 in UInt32(0) ... 255 {
            let draft = decode(0xC008_0000 | imm8)
            var fromOperands = ZATileMask.none
            for case let .zaTile(index, element) in draft.operands {
                fromOperands = fromOperands.union(
                    element.map { ZATileMask(tile: index, element: $0) } ?? .whole,
                )
            }
            #expect(fromOperands == draft.scalableWrites.zaMask, "imm8 \(imm8)")
        }
    }

    @Test func zeroIsNonStreamingSafeAndCarriesNoEffectFlags() {
        // ARM gates ZERO on ZA alone, not on streaming mode.
        for imm8 in UInt32(0) ... 255 {
            let draft = decode(0xC008_0000 | imm8)
            #expect(draft.scalableEffect == .none, "imm8 \(imm8)")
            #expect(draft.mnemonic == .zero)
            #expect(draft.semanticReads.isEmpty)
            #expect(draft.semanticWrites.isEmpty)
            #expect(draft.memoryAccess == .none)
        }
    }

    @Test func aZeroHoleFallsThroughToUndefined() {
        // Bit8 is reserved; setting it leaves the ZERO block entirely.
        #expect(decode(0xC008_0100).mnemonic == .undefined)
    }
}

/// Validates the ADDHA / ADDVA decoder — the predicated horizontal and vertical
/// accumulate into a `ZA` tile. The two differ by a single selector bit and the
/// two element widths differ by another, so all four combinations are asserted;
/// the `.d` forms also widen the tile field from two bits to three.
@Suite("SME core / ADDHA and ADDVA decode")
struct SMEAddHVDecodeTests {
    @Test func allFourBlocksResolveToTheirMnemonicAndElement() {
        #expect(text(0xC090_0000) == "addha za0.s, p0/m, p0/m, z0.s")
        #expect(text(0xC091_0000) == "addva za0.s, p0/m, p0/m, z0.s")
        #expect(text(0xC0D0_0000) == "addha za0.d, p0/m, p0/m, z0.d")
        #expect(text(0xC0D1_0000) == "addva za0.d, p0/m, p0/m, z0.d")
        #expect(decode(0xC090_0000).mnemonic == .addha)
        #expect(decode(0xC091_0000).mnemonic == .addva)
        #expect(decode(0xC0D0_0000).mnemonic == .addha)
        #expect(decode(0xC0D1_0000).mnemonic == .addva)
    }

    @Test func theTileFieldWidensWithTheElementSize() {
        // `.s` reads bits[1:0] (ZA0-3); `.d` reads bits[2:0] (ZA0-7). The bits
        // above each field are reserved, so the ranges do not overlap.
        for tile in UInt32(0) ... 3 {
            #expect(text(0xC090_0000 | tile) == "addha za\(tile).s, p0/m, p0/m, z0.s")
        }
        for tile in UInt32(0) ... 7 {
            #expect(text(0xC0D0_0000 | tile) == "addha za\(tile).d, p0/m, p0/m, z0.d")
        }
    }

    @Test func thePredicateOrderMatchesTheOuterProducts() {
        // Pn is bits[12:10] and renders first; Pm is bits[15:13] second.
        let encoding: UInt32 = 0xC090_0000 | (5 << 13) | (2 << 10) | (21 << 5) | 2
        #expect(text(encoding) == "addha za2.s, p2/m, p5/m, z21.s")
    }

    @Test func theAccumulatorTileIsReadAndWritten() {
        for (encoding, element) in [(UInt32(0xC090_0000), ScalarSize.s), (0xC0D0_0000, .d)] {
            let draft = decode(encoding | 1)
            let tile = ZATileMask(tile: 1, element: element)
            #expect(draft.scalableReads.zaMask == tile)
            #expect(draft.scalableWrites.zaMask == tile)
            #expect(draft.scalableEffect == [.readsStreamingMode, .partialWrite])
        }
    }

    @Test func onlyTheSingleSourceVectorIsRead() {
        // Unlike an outer product, ADDHA/ADDVA have no Zm field at all — bits
        // [31:16] are fixed — so exactly one vector is read.
        for zn in UInt32(0) ... 31 {
            let draft = decode(0xC090_0000 | (zn << 5))
            #expect(draft.semanticReads.contains(RegisterRef.simd(UInt8(zn))), "z\(zn)")
            #expect(draft.semanticReads.count == 1, "z\(zn)")
            #expect(draft.semanticWrites.isEmpty, "z\(zn)")
        }
    }

    @Test func bothPredicatesAreScalableReads() {
        let draft = decode(0xC090_0000 | (5 << 13) | (2 << 10))
        #expect(draft.scalableReads.predicateMask == (1 << 2) | (1 << 5))
    }

    @Test func anAccumulateHoleFallsThroughToUndefined() {
        // Bits[4:2] are reserved in the `.s` frame and bits[4:3] in the `.d`
        // frame; a set reserved bit leaves the block.
        for encoding: UInt32 in [0xC090_0004, 0xC090_0008, 0xC090_0010, 0xC0D0_0008, 0xC0D0_0010] {
            #expect(decode(encoding).mnemonic == .undefined, "0x\(String(encoding, radix: 16))")
        }
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

private let architecturalElementBytes: [ScalarSize: Int] = [.b: 1, .h: 2, .s: 4, .d: 8, .q: 16]

private func architecturalRows(tile tileIndex: UInt8, element: ScalarSize, rowCount: Int) -> Set<Int> {
    let stride = architecturalElementBytes[element]!
    var rows: Set<Int> = []
    var row = Int(tileIndex)
    while row < rowCount {
        rows.insert(row)
        row += stride
    }
    return rows
}

private let everyNamedTile: [(tile: UInt8, element: ScalarSize)] = {
    var tiles: [(tile: UInt8, element: ScalarSize)] = []
    for (element, count) in [(ScalarSize.b, 1), (.h, 2), (.s, 4), (.d, 8), (.q, 16)] {
        for tile in 0 ..< UInt8(count) {
            tiles.append((tile, element))
        }
    }
    return tiles
}()

/// Validates ZATileMask against the ARM ARM reference masks.
@Suite("ZATileMask / named tiles match the ARM ARM reference masks")
struct ZATileMaskReferenceTests {
    @Test func byteTileCoversTheWholeArray() {
        #expect(ZATileMask(tile: 0, element: .b).bits == 0xFFFF)
    }

    @Test func halfwordTilesInterleaveOddAndEvenPositions() {
        #expect(ZATileMask(tile: 0, element: .h).bits == 0x5555)
        #expect(ZATileMask(tile: 1, element: .h).bits == 0xAAAA)
    }

    @Test func wordTilesMatchTheFourReferenceMasks() {
        let expected: [UInt16] = [0x1111, 0x2222, 0x4444, 0x8888]
        for tile in 0 ..< 4 {
            #expect(ZATileMask(tile: UInt8(tile), element: .s).bits == expected[tile],
                    "ZA\(tile).S")
        }
    }

    @Test func doublewordTilesMatchTheEightReferenceMasks() {
        let expected: [UInt16] = [0x0101, 0x0202, 0x0404, 0x0808, 0x1010, 0x2020, 0x4040, 0x8080]
        for tile in 0 ..< 8 {
            #expect(ZATileMask(tile: UInt8(tile), element: .d).bits == expected[tile],
                    "ZA\(tile).D")
        }
    }

    @Test func quadwordTilesAreSingleQPositions() {
        for tile in 0 ..< 16 {
            #expect(ZATileMask(tile: UInt8(tile), element: .q).bits == UInt16(1) << tile,
                    "ZA\(tile).Q")
        }
    }

    @Test func tilesWithinATierPartitionTheArray() {
        for (element, count) in [(ScalarSize.b, 1), (.h, 2), (.s, 4), (.d, 8), (.q, 16)] {
            var accumulated = ZATileMask.none
            for tile in 0 ..< UInt8(count) {
                let mask = ZATileMask(tile: tile, element: element)
                #expect(!mask.overlaps(accumulated), "tile \(tile) of \(element) overlaps its own tier")
                accumulated = accumulated.union(mask)
            }
            #expect(accumulated.bits == 0xFFFF, "tier \(element) does not cover the array")
        }
    }
}

/// Validates `ZATileMask.overlaps` against an independent oracle.
@Suite("ZATileMask / overlap matches architectural row intersection")
struct ZATileMaskOverlapOracleTests {
    @Test(arguments: [16, 64, 256]) func overlapMatchesRowIntersectionAtEveryVectorLength(rowCount: Int) {
        var pairsChecked = 0
        for a in everyNamedTile {
            for b in everyNamedTile {
                let maskOverlap = ZATileMask(tile: a.tile, element: a.element)
                    .overlaps(ZATileMask(tile: b.tile, element: b.element))
                let rowsA = architecturalRows(tile: a.tile, element: a.element, rowCount: rowCount)
                let rowsB = architecturalRows(tile: b.tile, element: b.element, rowCount: rowCount)
                let architecturalOverlap = !rowsA.isDisjoint(with: rowsB)
                #expect(maskOverlap == architecturalOverlap,
                        "ZA\(a.tile).\(a.element) vs ZA\(b.tile).\(b.element) at \(rowCount) rows")
                pairsChecked += 1
            }
        }
        #expect(pairsChecked == 961, "expected the full 31 × 31 named-tile cross-product")
    }

    @Test func everyTileOverlapsTheByteTileThatContainsIt() {
        let byteTile = ZATileMask(tile: 0, element: .b)
        for tile in everyNamedTile {
            #expect(ZATileMask(tile: tile.tile, element: tile.element).overlaps(byteTile))
        }
    }

    @Test func containedTileOverlapsItsContainer() {
        #expect(ZATileMask(tile: 0, element: .s).overlaps(ZATileMask(tile: 0, element: .b)))
    }

    @Test func tilesInDifferentTiersWithDisjointStorageDoNotOverlap() {
        #expect(!ZATileMask(tile: 1, element: .h).overlaps(ZATileMask(tile: 0, element: .s)))
    }

    @Test func distinctQuadwordTilesNeverOverlap() {
        for a in 0 ..< 16 {
            for b in 0 ..< 16 where a != b {
                #expect(!ZATileMask(tile: UInt8(a), element: .q)
                    .overlaps(ZATileMask(tile: UInt8(b), element: .q)))
            }
        }
    }
}

/// Validates ZATileMask's set surface.
@Suite("ZATileMask / set algebra and construction")
struct ZATileMaskSetTests {
    @Test func noneIsTheEmptySet() {
        #expect(ZATileMask.none.bits == 0)
        #expect(ZATileMask.none.isEmpty)
    }

    @Test func defaultInitIsEmpty() {
        #expect(ZATileMask() == .none)
        #expect(ZATileMask().isEmpty)
    }

    @Test func wholeCoversEveryQPosition() {
        #expect(ZATileMask.whole.bits == 0xFFFF)
        #expect(!ZATileMask.whole.isEmpty)
    }

    @Test func wholeOverlapsEveryNamedTile() {
        for tile in everyNamedTile {
            #expect(ZATileMask.whole.overlaps(ZATileMask(tile: tile.tile, element: tile.element)))
        }
    }

    @Test func emptyMaskOverlapsNothing() {
        #expect(!ZATileMask.none.overlaps(.whole))
        #expect(!ZATileMask.none.overlaps(.none))
    }

    @Test func unionAccumulatesPositions() {
        let combined = ZATileMask(tile: 0, element: .s).union(ZATileMask(tile: 1, element: .s))
        #expect(combined.bits == 0x3333)
        #expect(!combined.isEmpty)
    }

    @Test func unionWithWholeSaturates() {
        #expect(ZATileMask(tile: 3, element: .d).union(.whole) == .whole)
    }

    @Test func unionWithEmptyIsIdentity() {
        let tile = ZATileMask(tile: 2, element: .s)
        #expect(tile.union(.none) == tile)
    }

    @Test func outOfRangeTileIndexReducesIntoRangeWithoutTrapping() {
        #expect(ZATileMask(tile: 4, element: .s) == ZATileMask(tile: 0, element: .s))
        #expect(ZATileMask(tile: 7, element: .s) == ZATileMask(tile: 3, element: .s))
        #expect(ZATileMask(tile: 2, element: .h) == ZATileMask(tile: 0, element: .h))
        #expect(ZATileMask(tile: 255, element: .q) == ZATileMask(tile: 15, element: .q))
        #expect(ZATileMask(tile: 255, element: .b) == ZATileMask(tile: 0, element: .b))
    }

    @Test func rawBitsInitRoundTrips() {
        #expect(ZATileMask(bits: 0x1234).bits == 0x1234)
    }

    @Test func equalMasksHashEqual() {
        let a = ZATileMask(tile: 1, element: .s)
        let b = ZATileMask(bits: 0x2222)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Pins ZATileMask's layout.
@Suite("ZATileMask / memory-layout invariant")
struct ZATileMaskLayoutTests {
    @Test func sizeIsExactlyTwoBytes() {
        #expect(MemoryLayout<ZATileMask>.size == 2)
    }
}

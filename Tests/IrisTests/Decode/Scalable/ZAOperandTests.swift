// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `ZATileSliceOperand`, the SME operand naming one row or column of
/// a tile.
@Suite("ZATileSliceOperand / tile slice and its sound ZA touch")
struct ZATileSliceOperandTests {
    @Test func horizontalSliceCarriesEveryField() {
        let slice = ZATileSliceOperand(
            tileIndex: 2, element: .s, direction: .horizontal,
            selectRegister: .w(12), offset: 3,
        )
        #expect(slice.tileIndex == 2)
        #expect(slice.element == .s)
        #expect(slice.direction == .horizontal)
        #expect(slice.selectRegister == RegisterRef.w(12))
        #expect(slice.offset == 3)
        #expect(slice.offsetHigh == nil)
    }

    @Test func verticalSliceCarriesItsDirection() {
        let slice = ZATileSliceOperand(
            tileIndex: 0, element: .d, direction: .vertical,
            selectRegister: .w(15), offset: 1,
        )
        #expect(slice.direction == .vertical)
    }

    @Test func sliceRangeCarriesItsHighEnd() {
        let range = ZATileSliceOperand(
            tileIndex: 1, element: .h, direction: .horizontal,
            selectRegister: .w(13), offset: 0, offsetHigh: 1,
        )
        #expect(range.offset == 0)
        #expect(range.offsetHigh == 1)
    }

    @Test func zaTouchIsTheWholeTileBecauseTheSliceIndexIsDynamic() {
        for element in [ScalarSize.b, .h, .s, .d, .q] {
            let slice = ZATileSliceOperand(
                tileIndex: 1, element: element, direction: .horizontal,
                selectRegister: .w(12), offset: 0,
            )
            #expect(slice.zaMask == ZATileMask(tile: 1, element: element), "\(element)")
        }
    }

    @Test func horizontalAndVerticalSlicesTouchTheSameTileStorage() {
        let horizontal = ZATileSliceOperand(
            tileIndex: 3, element: .s, direction: .horizontal,
            selectRegister: .w(12), offset: 0,
        )
        let vertical = ZATileSliceOperand(
            tileIndex: 3, element: .s, direction: .vertical,
            selectRegister: .w(12), offset: 0,
        )
        #expect(horizontal.zaMask == vertical.zaMask)
        #expect(horizontal.zaMask == ZATileMask(tile: 3, element: .s))
    }

    @Test func slicesOfOverlappingTilesReportOverlappingTouches() {
        let wordSlice = ZATileSliceOperand(
            tileIndex: 0, element: .s, direction: .horizontal,
            selectRegister: .w(12), offset: 0,
        )
        let byteSlice = ZATileSliceOperand(
            tileIndex: 0, element: .b, direction: .horizontal,
            selectRegister: .w(13), offset: 0,
        )
        #expect(wordSlice.zaMask.overlaps(byteSlice.zaMask))
    }

    @Test func selectRegisterIsAGprSemanticRead() {
        let slice = ZATileSliceOperand(
            tileIndex: 0, element: .s, direction: .horizontal,
            selectRegister: .w(14), offset: 2,
        )
        let reads = RegisterSet.empty.inserting(slice.selectRegister)
        #expect(reads.contains(RegisterRef.w(14)))
        #expect(reads.count == 1)
    }

    @Test func directionRawValuesAreStable() {
        #expect(ZATileSliceOperand.Direction.horizontal.rawValue == 0)
        #expect(ZATileSliceOperand.Direction.vertical.rawValue == 1)
        #expect(ZATileSliceOperand.Direction(rawValue: 0) == .horizontal)
        #expect(ZATileSliceOperand.Direction(rawValue: 1) == .vertical)
        #expect(ZATileSliceOperand.Direction(rawValue: 2) == nil)
    }

    @Test func equalSlicesHashEqual() {
        let a = ZATileSliceOperand(tileIndex: 1, element: .s, direction: .vertical,
                                   selectRegister: .w(12), offset: 1)
        let b = ZATileSliceOperand(tileIndex: 1, element: .s, direction: .vertical,
                                   selectRegister: .w(12), offset: 1)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates `ZAArrayVectorOperand`, the SME2 tile-agnostic view of `ZA` as an
/// array of SVL-bit vectors.
@Suite("ZAArrayVectorOperand / tile-agnostic array access")
struct ZAArrayVectorOperandTests {
    @Test func singleVectorAccessCarriesEveryField() {
        let vector = ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 2)
        #expect(vector.element == .s)
        #expect(vector.selectRegister == RegisterRef.w(8))
        #expect(vector.offset == 2)
        #expect(vector.offsetHigh == nil)
        #expect(vector.group == .none)
    }

    @Test func rangeAccessCarriesItsHighEnd() {
        let range = ZAArrayVectorOperand(element: .b, selectRegister: .w(9),
                                         offset: 0, offsetHigh: 3)
        #expect(range.offset == 0)
        #expect(range.offsetHigh == 3)
    }

    @Test func vectorGroupQualifierIsCarried() {
        let pair = ZAArrayVectorOperand(element: .d, selectRegister: .w(10),
                                        offset: 1, group: .vgx2)
        let quad = ZAArrayVectorOperand(element: .d, selectRegister: .w(11),
                                        offset: 1, group: .vgx4)
        #expect(pair.group == .vgx2)
        #expect(quad.group == .vgx4)
        #expect(pair != quad)
    }

    @Test func zaTouchIsTheWholeArrayRegardlessOfElementOrGroup() {
        for element in [ScalarSize.b, .h, .s, .d, .q] {
            for group in [ZAArrayVectorOperand.VectorGroup.none, .vgx2, .vgx4] {
                let vector = ZAArrayVectorOperand(element: element, selectRegister: .w(8),
                                                  offset: 0, group: group)
                #expect(vector.zaMask == .whole, "\(element) \(group)")
            }
        }
    }

    @Test func wholeArrayTouchOverlapsEveryNamedTile() {
        let vector = ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 0)
        #expect(vector.zaMask.overlaps(ZATileMask(tile: 0, element: .b)))
        #expect(vector.zaMask.overlaps(ZATileMask(tile: 15, element: .q)))
        #expect(vector.zaMask.overlaps(ZATileMask(tile: 3, element: .s)))
    }

    @Test func selectRegisterIsAGprSemanticRead() {
        let vector = ZAArrayVectorOperand(element: .s, selectRegister: .w(11), offset: 0)
        let reads = RegisterSet.empty.inserting(vector.selectRegister)
        #expect(reads.contains(RegisterRef.w(11)))
        #expect(reads.count == 1)
    }

    @Test func vectorGroupRawValuesAreStable() {
        #expect(ZAArrayVectorOperand.VectorGroup.none.rawValue == 0)
        #expect(ZAArrayVectorOperand.VectorGroup.vgx2.rawValue == 1)
        #expect(ZAArrayVectorOperand.VectorGroup.vgx4.rawValue == 2)
        #expect(ZAArrayVectorOperand.VectorGroup(rawValue: 0) == ZAArrayVectorOperand.VectorGroup.none)
        #expect(ZAArrayVectorOperand.VectorGroup(rawValue: 1) == ZAArrayVectorOperand.VectorGroup.vgx2)
        #expect(ZAArrayVectorOperand.VectorGroup(rawValue: 3) == nil)
    }

    @Test func equalOperandsHashEqual() {
        let a = ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 1, group: .vgx2)
        let b = ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 1, group: .vgx2)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates that a ZA access expressed as an operand round-trips into the
/// ``ScalableRegisterSet`` a decoder would record.
@Suite("ZA operands / recording a tile access as scalable dataflow state")
struct ZAOperandDataflowTests {
    @Test func accumulatingTileAccessAppearsInBothReadsAndWrites() {
        let destination = ZATileSliceOperand(
            tileIndex: 1, element: .s, direction: .horizontal,
            selectRegister: .w(12), offset: 0,
        )
        let reads = ScalableRegisterSet.empty.inserting(destination.zaMask)
        let writes = ScalableRegisterSet.empty.inserting(destination.zaMask)
        #expect(reads.zaMask == ZATileMask(tile: 1, element: .s))
        #expect(writes.zaMask == reads.zaMask)
        #expect(!reads.intersection(writes).isEmpty)
    }

    @Test func writingOneTileDoesNotKillADisjointTile() {
        let live = ScalableRegisterSet.empty.inserting(ZATileMask(tile: 1, element: .s))
        let written = ScalableRegisterSet.empty
            .inserting(ZATileSliceOperand(tileIndex: 0, element: .s, direction: .horizontal,
                                          selectRegister: .w(12), offset: 0).zaMask)
        #expect(live.subtracting(written) == live)
    }

    @Test func writingTheArrayVectorKillsEveryTile() {
        let live = ScalableRegisterSet.empty
            .inserting(ZATileMask(tile: 0, element: .s))
            .inserting(ZATileMask(tile: 2, element: .d))
        let written = ScalableRegisterSet.empty
            .inserting(ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 0).zaMask)
        #expect(live.subtracting(written).zaMask.isEmpty)
    }
}

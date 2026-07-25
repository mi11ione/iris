// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ScalableRegisterSet's bit layout — predicates P0-P15 at bits
/// [0..15], the ZA residue mask at [16..31], FFR at [32], ZT0 at [33]. The
/// layout is load-bearing: the four sub-fields must not collide, because
/// Piece 4's liveness unions and subtracts whole sets and would otherwise
/// corrupt one register kind's state while updating another's.
@Suite("ScalableRegisterSet / bit layout of the four register kinds")
struct ScalableRegisterSetLayoutTests {
    @Test func emptyHasNoBitsSet() {
        #expect(ScalableRegisterSet.empty.bits == 0)
        #expect(ScalableRegisterSet.empty.isEmpty)
    }

    @Test func defaultInitIsEmpty() {
        #expect(ScalableRegisterSet() == .empty)
        #expect(ScalableRegisterSet().isEmpty)
    }

    @Test func predicatesOccupyTheLowSixteenBits() {
        for index: UInt8 in 0 ... 15 {
            let set = ScalableRegisterSet.empty.insertingPredicate(index)
            #expect(set.bits == UInt64(1) << index, "P\(index)")
            #expect(!set.isEmpty)
        }
    }

    @Test func zaResidueOccupiesBitsSixteenToThirtyOne() {
        let set = ScalableRegisterSet.empty.inserting(ZATileMask(bits: 0x1111))
        #expect(set.bits == UInt64(0x1111) << 16)
    }

    @Test func wholeZAResidueFillsItsSixteenBitField() {
        let set = ScalableRegisterSet.empty.inserting(.whole)
        #expect(set.bits == 0xFFFF_0000)
    }

    @Test func ffrOccupiesBitThirtyTwo() {
        #expect(ScalableRegisterSet.empty.insertingFFR().bits == UInt64(1) << 32)
    }

    @Test func zt0OccupiesBitThirtyThree() {
        #expect(ScalableRegisterSet.empty.insertingZT0().bits == UInt64(1) << 33)
    }

    @Test func rawBitsInitRoundTrips() {
        #expect(ScalableRegisterSet(bits: 0xDEAD_BEEF).bits == 0xDEAD_BEEF)
    }

    @Test func theFourRegisterKindsDoNotCollide() {
        // One set carrying every kind at once: each accessor must read back
        // exactly its own field and nothing else.
        let set = ScalableRegisterSet.empty
            .insertingPredicate(3)
            .inserting(ZATileMask(tile: 1, element: .s))
            .insertingFFR()
            .insertingZT0()
        #expect(set.containsPredicate(3))
        #expect(!set.containsPredicate(4))
        #expect(set.predicateMask == 0b1000)
        #expect(set.zaMask == ZATileMask(tile: 1, element: .s))
        #expect(set.containsFFR)
        #expect(set.containsZT0)
    }

    @Test func insertingOneKindLeavesTheOthersUntouched() {
        let base = ScalableRegisterSet.empty.insertingPredicate(7)
        #expect(base.zaMask.isEmpty)
        #expect(!base.containsFFR)
        #expect(!base.containsZT0)

        let withZA = base.inserting(ZATileMask.whole)
        #expect(withZA.predicateMask == base.predicateMask)
        #expect(!withZA.containsFFR)
        #expect(!withZA.containsZT0)

        let withFFR = withZA.insertingFFR()
        #expect(withFFR.predicateMask == base.predicateMask)
        #expect(withFFR.zaMask == .whole)
        #expect(!withFFR.containsZT0)

        let withZT0 = withFFR.insertingZT0()
        #expect(withZT0.predicateMask == base.predicateMask)
        #expect(withZT0.zaMask == .whole)
        #expect(withZT0.containsFFR)
        #expect(withZT0.containsZT0)
    }
}

/// Validates ScalableRegisterSet's membership and insertion surface — the
/// predicate file (where the SME2 predicate-as-counter PN aliases the same
/// bits), the ZA residue, FFR, and ZT0. Insertion is idempotent and index
/// arguments outside the register file are masked into range, never trapped.
@Suite("ScalableRegisterSet / membership and insertion")
struct ScalableRegisterSetMembershipTests {
    @Test func emptySetContainsNothing() {
        let empty = ScalableRegisterSet.empty
        for index: UInt8 in 0 ... 15 {
            #expect(!empty.containsPredicate(index))
        }
        #expect(!empty.containsFFR)
        #expect(!empty.containsZT0)
        #expect(empty.zaMask.isEmpty)
        #expect(empty.predicateMask == 0)
    }

    @Test func predicateInsertRoundTripsForEveryIndex() {
        for index: UInt8 in 0 ... 15 {
            let set = ScalableRegisterSet.empty.insertingPredicate(index)
            #expect(set.containsPredicate(index))
            for other: UInt8 in 0 ... 15 where other != index {
                #expect(!set.containsPredicate(other), "P\(index) leaked into P\(other)")
            }
        }
    }

    @Test func allSixteenPredicatesFillThePredicateMask() {
        var set = ScalableRegisterSet.empty
        for index: UInt8 in 0 ... 15 {
            set = set.insertingPredicate(index)
        }
        #expect(set.predicateMask == 0xFFFF)
        #expect(set.bits == 0xFFFF)
    }

    @Test func predicateIndexAboveFifteenIsMaskedIntoRange() {
        // The predicate file has 16 registers; a wider index wraps rather
        // than trapping (the substrate's no-trap rule for encoding-derived
        // fields).
        #expect(ScalableRegisterSet.empty.insertingPredicate(16) ==
            ScalableRegisterSet.empty.insertingPredicate(0))
        #expect(ScalableRegisterSet.empty.insertingPredicate(255) ==
            ScalableRegisterSet.empty.insertingPredicate(15))
        let p0 = ScalableRegisterSet.empty.insertingPredicate(0)
        #expect(p0.containsPredicate(16))
        #expect(p0.containsPredicate(32))
    }

    @Test func predicateInsertIsIdempotent() {
        let once = ScalableRegisterSet.empty.insertingPredicate(9)
        #expect(once.insertingPredicate(9) == once)
    }

    @Test func predicateAsCounterAliasesTheSamePredicateBit() {
        // PN8 and P8 are the same physical register (they share a DWARF
        // register alias):
        // a counter operand's read must be visible to a mask operand's query.
        let counter = ScalablePredicateRef(registerIndex: 8, isCounter: true)
        let mask = ScalablePredicateRef(registerIndex: 8, isCounter: false)
        let set = ScalableRegisterSet.empty.insertingPredicate(counter.registerIndex)
        #expect(set.containsPredicate(mask.registerIndex))
    }

    @Test func zaMaskRoundTripsThroughTheSet() {
        for element in [ScalarSize.b, .h, .s, .d, .q] {
            let tile = ZATileMask(tile: 1, element: element)
            let set = ScalableRegisterSet.empty.inserting(tile)
            #expect(set.zaMask == tile, "\(element)")
        }
    }

    @Test func zaInsertsAccumulateAcrossTiles() {
        let set = ScalableRegisterSet.empty
            .inserting(ZATileMask(tile: 0, element: .s))
            .inserting(ZATileMask(tile: 2, element: .s))
        #expect(set.zaMask.bits == 0x4444 | 0x1111)
    }

    @Test func emptyZAInsertIsIdentity() {
        let set = ScalableRegisterSet.empty.insertingPredicate(1)
        #expect(set.inserting(ZATileMask.none) == set)
    }

    @Test func ffrInsertIsIdempotent() {
        let once = ScalableRegisterSet.empty.insertingFFR()
        #expect(once.containsFFR)
        #expect(once.insertingFFR() == once)
    }

    @Test func zt0InsertIsIdempotent() {
        let once = ScalableRegisterSet.empty.insertingZT0()
        #expect(once.containsZT0)
        #expect(once.insertingZT0() == once)
    }

    @Test func ffrAndZT0AreIndependentSingleRegisters() {
        let ffrOnly = ScalableRegisterSet.empty.insertingFFR()
        #expect(ffrOnly.containsFFR)
        #expect(!ffrOnly.containsZT0)

        let zt0Only = ScalableRegisterSet.empty.insertingZT0()
        #expect(zt0Only.containsZT0)
        #expect(!zt0Only.containsFFR)
    }

    @Test func equalSetsHashEqual() {
        let a = ScalableRegisterSet(bits: 0x1234)
        let b = ScalableRegisterSet(bits: 0x1234)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates ScalableRegisterSet's set algebra — union, intersection,
/// subtracting, isEmpty. This is the surface Piece 4's liveness computes
/// `use ∪ (out − def)` over, in lockstep with the base ``RegisterSet``, so
/// the two spaces can be treated uniformly. `subtracting` is the full-def
/// kill (PTRUE Pd, /Z ZA writes, non-predicated predicate writes).
@Suite("ScalableRegisterSet / set algebra for dataflow")
struct ScalableRegisterSetAlgebraTests {
    @Test func unionMergesEveryRegisterKind() {
        let reads = ScalableRegisterSet.empty
            .insertingPredicate(0)
            .insertingFFR()
        let writes = ScalableRegisterSet.empty
            .insertingPredicate(1)
            .inserting(ZATileMask(tile: 0, element: .s))
            .insertingZT0()
        let merged = reads.union(writes)
        #expect(merged.containsPredicate(0))
        #expect(merged.containsPredicate(1))
        #expect(merged.containsFFR)
        #expect(merged.containsZT0)
        #expect(merged.zaMask == ZATileMask(tile: 0, element: .s))
    }

    @Test func unionIsCommutative() {
        let a = ScalableRegisterSet(bits: 0xAAAA_AAAA)
        let b = ScalableRegisterSet(bits: 0x5555_5555)
        #expect(a.union(b) == b.union(a))
    }

    @Test func unionWithEmptyIsIdentity() {
        let a = ScalableRegisterSet.empty.insertingPredicate(4).insertingFFR()
        #expect(a.union(.empty) == a)
    }

    @Test func intersectionKeepsOnlyCommonRegisters() {
        let a = ScalableRegisterSet.empty
            .insertingPredicate(2)
            .insertingPredicate(3)
            .insertingFFR()
        let b = ScalableRegisterSet.empty
            .insertingPredicate(3)
            .insertingZT0()
        let common = a.intersection(b)
        #expect(!common.containsPredicate(2))
        #expect(common.containsPredicate(3))
        #expect(!common.containsFFR)
        #expect(!common.containsZT0)
    }

    @Test func intersectionOfDisjointSetsIsEmpty() {
        let a = ScalableRegisterSet.empty.insertingPredicate(0)
        let b = ScalableRegisterSet.empty.insertingPredicate(1)
        #expect(a.intersection(b).isEmpty)
    }

    @Test func subtractingRemovesTheKilledRegisters() {
        // A full-def kill: PTRUE P0 kills P0's liveness, leaving P1 live.
        let live = ScalableRegisterSet.empty
            .insertingPredicate(0)
            .insertingPredicate(1)
        let killed = ScalableRegisterSet.empty.insertingPredicate(0)
        let after = live.subtracting(killed)
        #expect(!after.containsPredicate(0))
        #expect(after.containsPredicate(1))
    }

    @Test func subtractingKillsAcrossEveryRegisterKind() {
        let live = ScalableRegisterSet.empty
            .insertingPredicate(5)
            .inserting(ZATileMask.whole)
            .insertingFFR()
            .insertingZT0()
        #expect(live.subtracting(live).isEmpty)
    }

    @Test func subtractingADisjointSetIsIdentity() {
        let live = ScalableRegisterSet.empty.insertingPredicate(2)
        let unrelated = ScalableRegisterSet.empty.insertingZT0()
        #expect(live.subtracting(unrelated) == live)
    }

    @Test func subtractingZAKillsOnlyTheOverlappingPositions() {
        // A /Z write to ZA0.S kills exactly its four Q positions; ZA1.S's
        // storage is untouched.
        let live = ScalableRegisterSet.empty
            .inserting(ZATileMask(tile: 0, element: .s))
            .inserting(ZATileMask(tile: 1, element: .s))
        let killed = ScalableRegisterSet.empty.inserting(ZATileMask(tile: 0, element: .s))
        let after = live.subtracting(killed)
        #expect(after.zaMask == ZATileMask(tile: 1, element: .s))
    }

    @Test func smstartClobberIsRepresentable() {
        // Entering streaming mode zeroes P0-P15 and FFR, and enabling ZA
        // zeroes the whole array. The SME decoder sets this on the record;
        // this proves the model can express it.
        var clobber = ScalableRegisterSet.empty
        for index: UInt8 in 0 ... 15 {
            clobber = clobber.insertingPredicate(index)
        }
        clobber = clobber.insertingFFR().inserting(.whole)
        #expect(clobber.predicateMask == 0xFFFF)
        #expect(clobber.containsFFR)
        #expect(clobber.zaMask == .whole)
        // The clobber kills every scalable register it names.
        #expect(clobber.subtracting(clobber).isEmpty)
        // ZT0 is not part of the SMSTART clobber.
        #expect(!clobber.containsZT0)
    }
}

/// Pins ScalableRegisterSet's layout — the whole set is exactly its UInt64
/// payload. Two of these ride inline on every ``InstructionRecord``
/// (scalableReads + scalableWrites), so a wider set would move the record's
/// pinned 57/64 size/stride.
@Suite("ScalableRegisterSet / memory-layout invariant")
struct ScalableRegisterSetLayoutPinTests {
    @Test func sizeIsExactlyEightBytes() {
        #expect(MemoryLayout<ScalableRegisterSet>.size == 8)
    }

    @Test func alignmentIsEightBytes() {
        #expect(MemoryLayout<ScalableRegisterSet>.alignment == 8)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates ScalableVectorRef — the `Zn` / `Zn.<T>` / `Zn.<T>[i]` operand.
/// The load-bearing property is the Z/V alias: `V_n` is the low 128 bits of
/// `Z_n`, so an SVE `Z_n` access and a NEON `V_n` access must land on the
/// same canonical ``RegisterSet`` bit (32+n). If they diverged, Piece 4 would
/// miss every def-use edge that crosses the NEON/SVE boundary.
@Suite("ScalableVectorRef / Z register operand and its V alias")
struct ScalableVectorRefTests {
    @Test func canonicalIndexIsThirtyTwoPlusRegisterNumber() {
        for index: UInt8 in 0 ... 31 {
            #expect(ScalableVectorRef(registerIndex: index).canonicalIndex == 32 + index)
        }
    }

    @Test func canonicalIndexMatchesTheNEONViewOfTheSameRegister() {
        // Z_n and V_n are one physical register: the SVE ref and the NEON
        // RegisterRef must produce the identical canonical index.
        for index: UInt8 in 0 ... 31 {
            #expect(ScalableVectorRef(registerIndex: index).canonicalIndex ==
                RegisterRef.simd(index).canonicalIndex, "Z\(index) vs V\(index)")
        }
    }

    @Test func registerIndexIsMaskedToFiveBits() {
        // Encoding-derived indices are masked into the register file, never
        // trapped (the substrate's no-trap factory rule).
        #expect(ScalableVectorRef(registerIndex: 32).registerIndex == 0)
        #expect(ScalableVectorRef(registerIndex: 0xFF).registerIndex == 31)
        #expect(ScalableVectorRef(registerIndex: 0xFF).canonicalIndex == 63)
    }

    @Test func plainZRegisterHasNoElementSuffix() {
        // LDR / STR / MOVPRFX name a bare Zn with no element size.
        let ref = ScalableVectorRef(registerIndex: 5)
        #expect(ref.registerIndex == 5)
        #expect(ref.element == nil)
        #expect(ref.elementIndex == nil)
    }

    @Test func sizedZRegisterCarriesItsElement() {
        for element in [ScalarSize.b, .h, .s, .d, .q] {
            let ref = ScalableVectorRef(registerIndex: 3, element: element)
            #expect(ref.element == element)
            #expect(ref.elementIndex == nil)
        }
    }

    @Test func indexedFormCarriesItsLaneIndex() {
        let ref = ScalableVectorRef(registerIndex: 7, element: .d, elementIndex: 1)
        #expect(ref.registerIndex == 7)
        #expect(ref.element == .d)
        #expect(ref.elementIndex == 1)
    }

    @Test func refsDifferingOnlyInElementAreDistinct() {
        let asS = ScalableVectorRef(registerIndex: 1, element: .s)
        let asD = ScalableVectorRef(registerIndex: 1, element: .d)
        #expect(asS != asD)
        // ...but they name the same physical register.
        #expect(asS.canonicalIndex == asD.canonicalIndex)
    }

    @Test func equalRefsHashEqual() {
        let a = ScalableVectorRef(registerIndex: 9, element: .s, elementIndex: 2)
        let b = ScalableVectorRef(registerIndex: 9, element: .s, elementIndex: 2)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

/// Validates RegisterSet's scalable-vector insert — the bridge that puts a
/// `Z_n` read or write into the same 64-bit mask the base ISA already uses,
/// on the bit `V_n` occupies. This is the whole Z/V aliasing model: it needs
/// no new state, and a NEON write is therefore visible to an SVE read.
@Suite("RegisterSet / Z register insertion shares the V register bit")
struct RegisterSetScalableVectorTests {
    @Test func insertingZSetsTheSimdBit() {
        let set = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 5))
        #expect(set.mask == UInt64(1) << 37)
        #expect(set.contains(RegisterRef.simd(5)))
    }

    @Test func zWriteIsVisibleToTheNEONView() {
        // Z3 written by an SVE instruction, read back as V3 by a NEON one.
        let writes = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 3, element: .s))
        #expect(writes.contains(RegisterRef.simd(3)))
        #expect(!writes.contains(RegisterRef.simd(4)))
        #expect(!writes.contains(RegisterRef.x(3)))
    }

    @Test func vWriteIsVisibleToTheSVEView() {
        // The reverse direction: a NEON V-write zeroes Z's high bits, so it
        // is a full-Z def; the shared bit captures it with no extra state.
        let neonWrite = RegisterSet.empty.inserting(RegisterRef.simd(12))
        let sveRead = ScalableVectorRef(registerIndex: 12, element: .d)
        #expect(neonWrite.contains(RegisterRef.simd(sveRead.registerIndex)))
        #expect(neonWrite.mask == UInt64(1) << UInt64(sveRead.canonicalIndex))
    }

    @Test func insertingEveryZFillsTheSimdHalfOfTheMask() {
        var set = RegisterSet.empty
        for index: UInt8 in 0 ... 31 {
            set = set.inserting(ScalableVectorRef(registerIndex: index))
        }
        #expect(set.mask == 0xFFFF_FFFF_0000_0000)
        #expect(set.count == 32)
    }

    @Test func insertingZIsIdempotent() {
        let once = RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: 8))
        #expect(once.inserting(ScalableVectorRef(registerIndex: 8, element: .h)) == once)
    }

    @Test func zAndGprBitsCoexist() {
        // A gather load reads Xn (base) and Zm (index), writes Zt.
        let reads = RegisterSet.empty
            .inserting(RegisterRef.x(1))
            .inserting(ScalableVectorRef(registerIndex: 2, element: .d))
        #expect(reads.contains(RegisterRef.x(1)))
        #expect(reads.contains(RegisterRef.simd(2)))
        #expect(reads.count == 2)
    }
}

/// Validates ScalableVectorGroup — the `{ Zn.<T>, ... }` multi-vector operand
/// (1 to 4 registers, consecutive or strided). The layout is load-bearing: it
/// decides which physical registers the group names, so a consecutive pair
/// `{Z0, Z1}` and a strided pair `{Z0, Z8}` must resolve differently.
@Suite("ScalableVectorGroup / member resolution by layout")
struct ScalableVectorGroupTests {
    @Test func consecutiveMembersStepByOne() {
        let group = ScalableVectorGroup(firstIndex: 4, count: 4, element: .s, layout: .consecutive)
        #expect(group.memberIndex(0) == 4)
        #expect(group.memberIndex(1) == 5)
        #expect(group.memberIndex(2) == 6)
        #expect(group.memberIndex(3) == 7)
    }

    @Test func consecutiveTripleCoversTheStructuredLoadForm() {
        // count 3 exists for the LD3/ST3 structured forms.
        let group = ScalableVectorGroup(firstIndex: 30, count: 3, element: .b, layout: .consecutive)
        #expect(group.count == 3)
        #expect(group.memberIndex(0) == 30)
        #expect(group.memberIndex(1) == 31)
        // Members wrap around the 32-register file rather than trapping.
        #expect(group.memberIndex(2) == 0)
    }

    @Test func stridedPairStepsByEight() {
        // Strided count-2 = {Zk, Zk+8} (stride 16 / count).
        let group = ScalableVectorGroup(firstIndex: 1, count: 2, element: .d, layout: .strided)
        #expect(group.memberIndex(0) == 1)
        #expect(group.memberIndex(1) == 9)
    }

    @Test func stridedQuadStepsByFour() {
        // Strided count-4 = {Zk, Zk+4, Zk+8, Zk+12}.
        let group = ScalableVectorGroup(firstIndex: 2, count: 4, element: .s, layout: .strided)
        #expect(group.memberIndex(0) == 2)
        #expect(group.memberIndex(1) == 6)
        #expect(group.memberIndex(2) == 10)
        #expect(group.memberIndex(3) == 14)
    }

    @Test func consecutiveAndStridedPairsNameDifferentRegisters() {
        let consecutive = ScalableVectorGroup(firstIndex: 0, count: 2, element: .s, layout: .consecutive)
        let strided = ScalableVectorGroup(firstIndex: 0, count: 2, element: .s, layout: .strided)
        #expect(consecutive.memberIndex(1) == 1)
        #expect(strided.memberIndex(1) == 8)
        #expect(consecutive != strided)
    }

    @Test func singleRegisterGroupNamesOnlyItsFirstRegister() {
        let group = ScalableVectorGroup(firstIndex: 17, count: 1, element: .h, layout: .consecutive)
        #expect(group.count == 1)
        #expect(group.memberIndex(0) == 17)
    }

    @Test func zeroCountStridedGroupResolvesWithoutDividingByZero() {
        // count == 0 cannot come from a real encoding, but the member stride
        // is `16 / count` — the guard keeps the accessor total instead of
        // trapping on a malformed group.
        let group = ScalableVectorGroup(firstIndex: 3, count: 0, element: .s, layout: .strided)
        #expect(group.count == 0)
        #expect(group.memberIndex(0) == 3)
        #expect(group.memberIndex(1) == 4)
    }

    @Test func firstIndexIsMaskedToFiveBits() {
        let group = ScalableVectorGroup(firstIndex: 0xFF, count: 2, element: .b, layout: .consecutive)
        #expect(group.firstIndex == 31)
        #expect(group.memberIndex(0) == 31)
        #expect(group.memberIndex(1) == 0)
    }

    @Test func memberIndexBeyondTheGroupWrapsIntoTheRegisterFile() {
        // j >= count is out of range; the accessor stays total and wraps.
        let group = ScalableVectorGroup(firstIndex: 28, count: 2, element: .s, layout: .consecutive)
        #expect(group.memberIndex(5) == 1)
    }

    @Test func groupMembersMapToTheSharedSimdBits() {
        // The group's semantic reads are the union of its members' canonical
        // indices — the same Z/V bits a single Zn ref would set.
        let group = ScalableVectorGroup(firstIndex: 6, count: 2, element: .s, layout: .consecutive)
        var reads = RegisterSet.empty
        for j in 0 ..< group.count {
            reads = reads.inserting(ScalableVectorRef(registerIndex: group.memberIndex(j)))
        }
        #expect(reads.contains(RegisterRef.simd(6)))
        #expect(reads.contains(RegisterRef.simd(7)))
        #expect(reads.count == 2)
    }

    @Test func layoutRawValuesAreStable() {
        #expect(ScalableVectorGroup.Layout.consecutive.rawValue == 0)
        #expect(ScalableVectorGroup.Layout.strided.rawValue == 1)
        #expect(ScalableVectorGroup.Layout(rawValue: 0) == .consecutive)
        #expect(ScalableVectorGroup.Layout(rawValue: 1) == .strided)
        #expect(ScalableVectorGroup.Layout(rawValue: 2) == nil)
    }

    @Test func equalGroupsHashEqual() {
        let a = ScalableVectorGroup(firstIndex: 2, count: 4, element: .s, layout: .strided)
        let b = ScalableVectorGroup(firstIndex: 2, count: 4, element: .s, layout: .strided)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

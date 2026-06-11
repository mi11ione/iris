// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates RegisterRef factories — every named register form, role
/// disambiguation at canonical-index 31, and width selection.
@Suite("RegisterRef / factory constructors")
struct RegisterRefFactoryTests {
    @Test func wFactoryProducesGeneralW32() {
        let r = RegisterRef.w(3)
        #expect(r.canonicalIndex == 3)
        #expect(r.role == .general)
        #expect(r.width == .w32)
        #expect(r.isGPR)
        #expect(!r.isSIMD)
        #expect(!r.isStackPointer)
        #expect(!r.isZeroRegister)
    }

    @Test func xFactoryProducesGeneralX64() {
        let r = RegisterRef.x(7)
        #expect(r.canonicalIndex == 7)
        #expect(r.role == .general)
        #expect(r.width == .x64)
        #expect(r.isGPR)
    }

    @Test func wzrFactoryProducesZeroRegisterW32() {
        let r = RegisterRef.wzr()
        #expect(r.canonicalIndex == 31)
        #expect(r.role == .zeroRegister)
        #expect(r.width == .w32)
        #expect(r.isGPR)
        #expect(r.isZeroRegister)
        #expect(!r.isStackPointer)
    }

    @Test func xzrFactoryProducesZeroRegisterX64() {
        let r = RegisterRef.xzr()
        #expect(r.canonicalIndex == 31)
        #expect(r.role == .zeroRegister)
        #expect(r.width == .x64)
        #expect(r.isZeroRegister)
    }

    @Test func wspFactoryProducesStackPointerW32() {
        let r = RegisterRef.wsp()
        #expect(r.canonicalIndex == 31)
        #expect(r.role == .stackPointer)
        #expect(r.width == .w32)
        #expect(r.isStackPointer)
        #expect(!r.isZeroRegister)
    }

    @Test func spFactoryProducesStackPointerX64() {
        let r = RegisterRef.sp()
        #expect(r.canonicalIndex == 31)
        #expect(r.role == .stackPointer)
        #expect(r.width == .x64)
        #expect(r.isStackPointer)
    }

    @Test func simdFactoryProducesVectorImplied() {
        let r = RegisterRef.simd(0)
        #expect(r.canonicalIndex == 32)
        #expect(r.role == .general)
        #expect(r.width == .vectorImplied)
        #expect(r.isSIMD)
        #expect(!r.isGPR)
    }

    @Test func simdFactoryAtIndex31MapsToCanonical63() {
        let r = RegisterRef.simd(31)
        #expect(r.canonicalIndex == 63)
        #expect(r.isSIMD)
    }

    @Test func wAndXAtSameIndexShareCanonicalIndexButDifferInWidth() {
        let w = RegisterRef.w(5)
        let x = RegisterRef.x(5)
        #expect(w.canonicalIndex == x.canonicalIndex)
        #expect(w.width != x.width)
        #expect(w != x)
    }

    @Test func wspAndWzrShareEncodingButDifferInRole() {
        let wsp = RegisterRef.wsp()
        let wzr = RegisterRef.wzr()
        #expect(wsp.canonicalIndex == wzr.canonicalIndex)
        #expect(wsp.role != wzr.role)
        #expect(wsp != wzr)
    }

    @Test func gprPredicateExcludesAllSIMDIndices() {
        for n: UInt8 in 0 ... 31 {
            #expect(!RegisterRef.simd(n).isGPR)
        }
    }

    @Test func memberwiseInitRespectsAllFields() {
        let r = RegisterRef(canonicalIndex: 42, role: .general, width: .vectorImplied)
        #expect(r.canonicalIndex == 42)
        #expect(r.role == .general)
        #expect(r.width == .vectorImplied)
    }
}

/// Validates RegisterRole / RegisterWidth — closed-set enums backing
/// the operand-level register identity.
@Suite("RegisterRole and RegisterWidth / raw values")
struct RegisterRoleWidthTests {
    @Test func roleRawValuesStable() {
        #expect(RegisterRole.general.rawValue == 0)
        #expect(RegisterRole.stackPointer.rawValue == 1)
        #expect(RegisterRole.zeroRegister.rawValue == 2)
    }

    @Test func widthRawValuesStable() {
        #expect(RegisterWidth.w32.rawValue == 0)
        #expect(RegisterWidth.x64.rawValue == 1)
        #expect(RegisterWidth.vectorImplied.rawValue == 2)
    }

    @Test func roleRawValueRoundTrip() {
        for raw: UInt8 in 0 ... 2 {
            #expect(RegisterRole(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func widthRawValueRoundTrip() {
        for raw: UInt8 in 0 ... 2 {
            #expect(RegisterWidth(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func roleOutOfRangeRawReturnsNil() {
        #expect(RegisterRole(rawValue: 3) == nil)
    }

    @Test func widthOutOfRangeRawReturnsNil() {
        #expect(RegisterWidth(rawValue: 3) == nil)
    }
}

/// Validates RegisterSet — the 64-bit semantic-reads / -writes bitmask
/// over canonical GPR (0..31) and SIMD (32..63) indices.
@Suite("RegisterSet / bitmask operations")
struct RegisterSetTests {
    @Test func emptyHasZeroMask() {
        #expect(RegisterSet.empty.mask == 0)
        #expect(RegisterSet().mask == 0)
    }

    @Test func defaultInitIsEmpty() {
        #expect(RegisterSet() == .empty)
    }

    @Test func containsRespectsBitAtRegisterIndex() {
        let set = RegisterSet(mask: 0b1100)
        #expect(set.contains(RegisterRef.x(2)))
        #expect(set.contains(RegisterRef.x(3)))
        #expect(!set.contains(RegisterRef.x(0)))
        #expect(!set.contains(RegisterRef.x(1)))
    }

    @Test func containsRejectsRegistersWithCanonicalIndexAt64OrHigher() {
        let synthetic = RegisterRef(canonicalIndex: 64, role: .general, width: .x64)
        let set = RegisterSet(mask: UInt64.max)
        #expect(!set.contains(synthetic))
    }

    @Test func unionMergesBits() {
        let a = RegisterSet(mask: 0b0011)
        let b = RegisterSet(mask: 0b1100)
        #expect(a.union(b).mask == 0b1111)
    }

    @Test func unionIsCommutative() {
        let a = RegisterSet(mask: 0xAA)
        let b = RegisterSet(mask: 0x55)
        #expect(a.union(b) == b.union(a))
    }

    @Test func intersectionKeepsCommonBits() {
        let a = RegisterSet(mask: 0b1110)
        let b = RegisterSet(mask: 0b0111)
        #expect(a.intersection(b).mask == 0b0110)
    }

    @Test func insertingAddsRegisterBit() {
        let zero = RegisterSet.empty
        let added = zero.inserting(RegisterRef.x(5))
        #expect(added.mask == (UInt64(1) << 5))
        #expect(added.contains(RegisterRef.x(5)))
    }

    @Test func insertingIgnoresOutOfRangeIndex() {
        let synthetic = RegisterRef(canonicalIndex: 100, role: .general, width: .x64)
        let after = RegisterSet.empty.inserting(synthetic)
        #expect(after == .empty)
    }

    @Test func insertingTwiceIsIdempotent() {
        let a = RegisterSet.empty.inserting(RegisterRef.x(3))
        let b = a.inserting(RegisterRef.x(3))
        #expect(a == b)
    }

    @Test func gprAndSimdBitsCoexist() {
        let mixed = RegisterSet.empty
            .inserting(RegisterRef.x(5))
            .inserting(RegisterRef.simd(10))
        #expect(mixed.contains(RegisterRef.x(5)))
        #expect(mixed.contains(RegisterRef.simd(10)))
        #expect(mixed.mask == ((UInt64(1) << 5) | (UInt64(1) << (32 + 10))))
    }

    @Test func equalSetsHashEqual() {
        let a = RegisterSet(mask: 0x1234)
        let b = RegisterSet(mask: 0x1234)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }
}

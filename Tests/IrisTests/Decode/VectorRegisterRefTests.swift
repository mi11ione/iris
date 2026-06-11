// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates VectorRegisterRef + VectorView + VectorArrangement +
/// ScalarSize — the SIMD operand grammar's three view shapes.
@Suite("VectorRegisterRef / view shapes")
struct VectorRegisterRefTests {
    @Test func registerIndexIsMaskedToFiveBits() {
        let r = VectorRegisterRef(registerIndex: 0xFF, view: .scalar(size: .d))
        #expect(r.registerIndex == 31)
    }

    @Test func fullViewCarriesArrangement() {
        let r = VectorRegisterRef(registerIndex: 5, view: .full(arrangement: .s4))
        #expect(r.registerIndex == 5)
        #expect(r.view == .full(arrangement: .s4))
    }

    @Test func scalarViewCarriesSize() {
        let r = VectorRegisterRef(registerIndex: 10, view: .scalar(size: .q))
        #expect(r.view == .scalar(size: .q))
    }

    @Test func elementViewCarriesArrangementAndIndex() {
        let r = VectorRegisterRef(registerIndex: 7, view: .element(arrangement: .s4, index: 2))
        #expect(r.view == .element(arrangement: .s4, index: 2))
    }

    @Test func equalReferencesHashEqual() {
        let a = VectorRegisterRef(registerIndex: 3, view: .full(arrangement: .b16))
        let b = VectorRegisterRef(registerIndex: 3, view: .full(arrangement: .b16))
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func differentViewsOnSameIndexAreDistinct() {
        let full = VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .d2))
        let scalar = VectorRegisterRef(registerIndex: 0, view: .scalar(size: .d))
        #expect(full != scalar)
    }
}

/// Validates VectorArrangement — the 8 named element-size × count
/// shapes (8B..2D).
@Suite("VectorArrangement / raw values and exhaustive cases")
struct VectorArrangementTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(VectorArrangement.b8.rawValue == 0)
        #expect(VectorArrangement.b16.rawValue == 1)
        #expect(VectorArrangement.h4.rawValue == 2)
        #expect(VectorArrangement.h8.rawValue == 3)
        #expect(VectorArrangement.s2.rawValue == 4)
        #expect(VectorArrangement.s4.rawValue == 5)
        #expect(VectorArrangement.d1.rawValue == 6)
        #expect(VectorArrangement.d2.rawValue == 7)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 9 {
            #expect(VectorArrangement(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeReturnsNil() {
        #expect(VectorArrangement(rawValue: 10) == nil)
    }
}

/// Validates ScalarSize — the 5 named SIMD scalar widths (B/H/S/D/Q).
@Suite("ScalarSize / raw values and exhaustive cases")
struct ScalarSizeTests {
    @Test func everyCaseHasStableRawValue() {
        #expect(ScalarSize.b.rawValue == 0)
        #expect(ScalarSize.h.rawValue == 1)
        #expect(ScalarSize.s.rawValue == 2)
        #expect(ScalarSize.d.rawValue == 3)
        #expect(ScalarSize.q.rawValue == 4)
    }

    @Test func rawValueRoundTrip() {
        for raw: UInt8 in 0 ... 4 {
            #expect(ScalarSize(rawValue: raw)?.rawValue == raw)
        }
    }

    @Test func outOfRangeReturnsNil() {
        #expect(ScalarSize(rawValue: 5) == nil)
    }
}

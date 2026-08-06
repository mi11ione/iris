// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SME core decoder for SME-core.
enum SMECoreDecode {
    /// Decode an in-scope SME-core word.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch e & 0xE000_0000 {
        case 0x8000_0000, 0xA000_0000: decodeOuterProduct(e, a, &sink)
        case 0xC000_0000: decodeMoveZero(e, a, &sink)
        default: decodeMemory(e, a, &sink)
        }
    }

    /// Second SIMD/scalable register.
    @inline(__always) static func zn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    /// Third SIMD/scalable register.
    @inline(__always) static func zm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    /// Destination vector — bits[4:0] (`Zd`, MOVA extract).
    @inline(__always) static func zd(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    /// First governing predicate.
    @inline(__always) static func pn3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 10) & 0x7)
    }

    /// Second governing predicate.
    @inline(__always) static func pm3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 13) & 0x7)
    }

    /// Base GPR — bits[9:5] (`Rn`/`SP`).
    @inline(__always) static func rn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    /// Index GPR — bits[20:16] (`Rm`; 31 ⇒ no index).
    @inline(__always) static func rm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    /// Slice-select field — bits[14:13] (2-bit `Rv`; the register is
    /// `W12+Rv`).
    @inline(__always) static func rv(_ e: UInt32) -> UInt8 {
        UInt8((e >> 13) & 0x3)
    }

    /// True for a vertical tile slice (bit15 = `V`).
    @inline(__always) static func isVertical(_ e: UInt32) -> Bool {
        e & 0x8000 != 0
    }

    /// The vector-select GPR `Wv` (`W12`-`W15`).
    @inline(__always) static func selectRegister(_ e: UInt32) -> RegisterRef {
        .w(12 &+ rv(e))
    }

    /// Split a 4-bit tile|offset nibble into `(tileIndex, sliceOffset)`.
    @inline(__always)
    static func tileAndOffset(_ element: ScalarSize, _ nibble: UInt8) -> (tile: UInt8, offset: UInt8) {
        switch element {
        case .b: (0, nibble & 0xF)
        case .h: ((nibble >> 3) & 0x1, nibble & 0x7)
        case .s: ((nibble >> 2) & 0x3, nibble & 0x3)
        case .d: ((nibble >> 1) & 0x7, nibble & 0x1)
        case .q: (nibble & 0xF, 0)
        }
    }

    /// A `ZA` tile-slice operand `zaN{h|v}.<T>[Wv, #off]`.
    @inline(__always)
    static func tileSlice(_ e: UInt32, _ element: ScalarSize, _ nibble: UInt8) -> ZATileSliceOperand {
        let (tile, offset) = tileAndOffset(element, nibble)
        return ZATileSliceOperand(
            tileIndex: tile,
            element: element,
            direction: isVertical(e) ? .vertical : .horizontal,
            selectRegister: selectRegister(e),
            offset: offset,
        )
    }

    /// A governing predicate `Pg` with the given qualifier (governing role).
    @inline(__always)
    static func govern(_ index: UInt8, _ qualifier: PredicateQualifier) -> Operand {
        .scalablePredicate(ScalablePredicateRef(registerIndex: index, qualifier: qualifier, role: .governing))
    }

    /// A plain scalable vector `Zn.<T>`.
    @inline(__always)
    static func vec(_ index: UInt8, _ element: ScalarSize) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element))
    }

    /// The Z/V register-set bit `32+n`.
    @inline(__always)
    static func vecMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: index))
    }

    /// The GPR register-set bit for `Xn`/`Wn` at index `n` (`SP` at 31).
    @inline(__always)
    static func gprMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(index == 31 ? RegisterRef.sp() : RegisterRef.x(index))
    }

    /// A single-predicate read set.
    @inline(__always)
    static func predRead(_ index: UInt8) -> ScalableRegisterSet {
        ScalableRegisterSet.empty.insertingPredicate(index)
    }

    /// A well-formed in-scope UNDEFINED SME record (`category = .sme`, raw
    /// encoding preserved), matching llvm-mc's empty output for a rejected
    /// in-scope hole.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sme)
    }
}

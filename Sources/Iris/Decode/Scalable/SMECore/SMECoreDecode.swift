// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME core decoder. Entry + coarse dispatch: the
// top three bits (bits[31:29]) select the family — 100/101 outer products,
// 110 MOVA/ZERO/ADDHA/ADDVA, 111 ZA load/store. Called only from
// `SMEDecoder.decode` when `isSMECoreEncoding` holds, so `decode` is total
// over SME-core's domain: every path returns a real record or a well-formed
// UNDEFINED (`.undefined`, `.sme`) for the genuine in-scope holes.
//
// Shared field extractors, operand builders, and mask builders used by every
// group decoder (outer product / move-zero / memory) live here. Records the
// operand structure only — ZA matrix-shape and effective-address computation
// are the caller's.

/// The SME core decoder for SME-core.
enum SMECoreDecode {
    /// Decode an in-scope SME-core word. Precondition (by construction, not
    /// asserted): `isSMECoreEncoding(e)`.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch e & 0xE000_0000 {
        case 0x8000_0000, 0xA000_0000: decodeOuterProduct(e, a, &sink)
        case 0xC000_0000: decodeMoveZero(e, a, &sink)
        // 111 — ZA load/store. The precondition fixes bit31, so 100/101/110
        // above leave this as the only remaining value of bits[31:29] and the
        // dispatch needs no unreachable UNDEFINED arm.
        default: decodeMemory(e, a, &sink)
        }
    }

    // MARK: - shared field extractors

    /// Second SIMD/scalable register — bits[9:5] (`Zn`).
    @inline(__always) static func zn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    /// Third SIMD/scalable register — bits[20:16] (`Zm`).
    @inline(__always) static func zm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    /// Destination vector — bits[4:0] (`Zd`, MOVA extract).
    @inline(__always) static func zd(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    /// First governing predicate — bits[12:10] (`Pn`/`Pg`, P0-P7).
    @inline(__always) static func pn3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 10) & 0x7)
    }

    /// Second governing predicate — bits[15:13] (`Pm`, P0-P7).
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

    /// Slice-select field — bits[14:13] (2-bit `Rv`; the register is `W12+Rv`).
    @inline(__always) static func rv(_ e: UInt32) -> UInt8 {
        UInt8((e >> 13) & 0x3)
    }

    /// True for a vertical tile slice (bit15 = `V`).
    @inline(__always) static func isVertical(_ e: UInt32) -> Bool {
        e & 0x8000 != 0
    }

    // MARK: - shared operand / register builders

    /// The vector-select GPR `Wv` (`W12`-`W15`) — a semantic GPR read.
    @inline(__always) static func selectRegister(_ e: UInt32) -> RegisterRef {
        .w(12 &+ rv(e))
    }

    /// Split a 4-bit tile|offset nibble into `(tileIndex, sliceOffset)` for the
    /// element size: the tile field grows and the offset shrinks as
    /// the element narrows — B: off4; H: tile[3]+off3; S: tile[3:2]+off2;
    /// D: tile[3:1]+off1; Q: tile[3:0], offset implicit 0.
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

    // MARK: - shared mask builders

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

    // MARK: - undefined

    /// A well-formed in-scope UNDEFINED SME record (`category = .sme`, raw
    /// encoding preserved), matching llvm-mc's empty output for a rejected
    /// in-scope hole.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sme)
    }
}

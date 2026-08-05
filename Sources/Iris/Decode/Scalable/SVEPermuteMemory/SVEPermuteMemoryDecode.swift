// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 permute, memory, and crypto decoder. Entry +
// region dispatch: the top byte selects the region — bit31=1 is the
// memory family (routed by the class masksa), 0x05 is the permute
// family, 0x44 the quadword permute cluster (TBLQ/UZPQ/ZIPQ), 0x45 the crypto/
// LUT cluster. Called only from `SVEDecoder.decode` when
// `isSVEPermuteMemoryCryptoEncoding` holds, so `decode` is total over SVE-permute/memory's
// domain: every path returns a real record or a well-formed UNDEFINED
// (`.undefined`, `.sve`) for the genuine in-scope holes (reserved dtype/opc/
// nregs, illegal size).
//
// Shared field extraction, operand builders, and mask builders used by every
// group decoder live here.

/// The SVE / SVE2 permute / memory / crypto decoder for SVE-permute/memory.
enum SVEPermuteMemoryDecode {
    /// Decode an in-scope SVE permute/memory/crypto word. Precondition (by
    /// construction, not asserted): `isSVEPermuteMemoryCryptoEncoding(e)`.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if e & 0x8000_0000 != 0 {
            return decodeMemory(e, a, &sink)
        }
        switch (e >> 24) & 0xFF {
        case 0x05: return decodePermute(e, a, &sink)
        case 0x44: return decodeQuadwordPermute(e, a, &sink) // TBLQ/UZPQ/ZIPQ
        default: return decodeCrypto(e, a, &sink) // 0x45 crypto / LUT
        }
    }

    // MARK: - shared field extractors

    /// Destination / first register — bits[4:0] (`Zt`/`Zd`/`Zdn`/`Pd`/`Rd`).
    @inline(__always) static func rd(_ e: UInt32) -> UInt8 {
        UInt8(e & 0x1F)
    }

    /// Second register — bits[9:5] (`Zn`/`Rn`/`Pn`/`Vn`).
    @inline(__always) static func rn(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0x1F)
    }

    /// Third register — bits[20:16] (`Zm`/`Rm`/`Vm`/`imm5`).
    @inline(__always) static func rm(_ e: UInt32) -> UInt8 {
        UInt8((e >> 16) & 0x1F)
    }

    /// Governing predicate — bits[12:10] (3-bit `Pg`).
    @inline(__always) static func pg3(_ e: UInt32) -> UInt8 {
        UInt8((e >> 10) & 0x7)
    }

    /// Predicate operand at bits[8:5] (4-bit `Pn` in the predicate-permute forms).
    @inline(__always) static func pn4(_ e: UInt32) -> UInt8 {
        UInt8((e >> 5) & 0xF)
    }

    /// Predicate destination at bits[3:0] (4-bit `Pd` in predicate forms).
    @inline(__always) static func pd4(_ e: UInt32) -> UInt8 {
        UInt8(e & 0xF)
    }

    /// Size field bits[23:22].
    @inline(__always) static func sz2(_ e: UInt32) -> UInt8 {
        UInt8((e >> 22) & 0x3)
    }

    /// Element size from a 2-bit size field (00→B, 01→H, 10→S, 11→D).
    @inline(__always) static func esize(_ sz: UInt8) -> ScalarSize {
        switch sz {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    // MARK: - shared operand builders

    /// A plain scalable vector `Zn.<T>`.
    @inline(__always)
    static func vec(_ index: UInt8, _ element: ScalarSize) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element))
    }

    /// A plain scalable vector with no element suffix (`Zn`) — PMOV / LDR-Z.
    @inline(__always)
    static func vecPlain(_ index: UInt8) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index))
    }

    /// An indexed scalable vector element `Zn.<T>[i]` (DUPQ / crypto index).
    @inline(__always)
    static func vecIndexed(_ index: UInt8, _ element: ScalarSize, lane: UInt8) -> Operand {
        .scalableVector(ScalableVectorRef(registerIndex: index, element: element, elementIndex: lane))
    }

    /// A governing predicate `Pg` with the given qualifier and governing role.
    @inline(__always)
    static func govern(_ index: UInt8, _ qualifier: PredicateQualifier) -> Operand {
        .scalablePredicate(ScalablePredicateRef(registerIndex: index, qualifier: qualifier, role: .governing))
    }

    /// A predicate source `Pn.<T>` (governing role, element suffix) — the
    /// predicate-permute forms.
    @inline(__always)
    static func predElem(_ index: UInt8, _ element: ScalarSize, role: ScalablePredicateRef.Role) -> Operand {
        .scalablePredicate(ScalablePredicateRef(registerIndex: index, element: element, role: role))
    }

    /// A multi-vector group `{ Z(first).<T> ... }` (structured / crypto / TBL).
    @inline(__always)
    static func group(_ first: UInt8, count: UInt8, _ element: ScalarSize) -> Operand {
        .scalableVectorGroup(ScalableVectorGroup(
            firstIndex: first, count: count, element: element, layout: .consecutive,
        ))
    }

    /// A GPR operand of the given width (LASTA/B/INSR/CLASTA/B scalar). Index 31
    /// is the zero register (`wzr`/`xzr`), not SP, in these data forms.
    @inline(__always)
    static func gpr(_ index: UInt8, _ width: ScalarSize) -> Operand {
        // b/h/s destinations render `Wn`; d renders `Xn`.
        if index == 31 { return .register(width == .d ? .xzr() : .wzr()) }
        return .register(width == .d ? .x(index) : .w(index))
    }

    /// A SIMD&FP scalar register of the element width (`Bn`/`Hn`/`Sn`/`Dn`).
    @inline(__always)
    static func simdScalar(_ index: UInt8, _ width: ScalarSize) -> Operand {
        .vectorRegister(VectorRegisterRef(registerIndex: index, view: .scalar(size: width)))
    }

    /// The prefetch-operation operand (5-bit raw carried, 4 significant bits).
    @inline(__always)
    static func prfop(_ e: UInt32) -> Operand {
        .prefetchOperation(PrefetchOperation(rawValue: UInt8(e & 0xF)))
    }

    // MARK: - shared mask builders

    /// The Z/V register-set bit `32+n` for a scalable vector.
    @inline(__always)
    static func vecMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: index))
    }

    /// The Z/V bits for every member of a consecutive group.
    @inline(__always)
    static func groupMask(_ first: UInt8, count: UInt8) -> RegisterSet {
        var set = RegisterSet.empty
        var j: UInt8 = 0
        while j < count {
            set = set.inserting(ScalableVectorRef(registerIndex: (first &+ j) & 0x1F))
            j &+= 1
        }
        return set
    }

    /// The GPR register-set bit for `Xn`/`Wn` at index `n`.
    @inline(__always)
    static func gprMask(_ index: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(RegisterRef.x(index))
    }

    /// A governing-predicate read set.
    @inline(__always)
    static func predRead(_ index: UInt8) -> ScalableRegisterSet {
        ScalableRegisterSet.empty.insertingPredicate(index)
    }

    // MARK: - undefined

    /// A well-formed in-scope UNDEFINED SVE record (`category = .sve`, raw
    /// encoding preserved), matching llvm-mc's empty output for rejected words.
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}

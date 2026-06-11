// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Shared helpers for SIMD/FP sub-decoders: arrangement and
// scalar-size decoding from encoding bits, vector-operand factories,
// register-set semantics, immediate decoding for AdvSIMD modified-
// immediate, and FP-immediate decoding (the 8-bit "ABCDEFGH" → IEEE
// 754 bit-pattern mapping shared by FMOV-imm and vector-FMOV-imm).
//
// Public extensions on ``VectorArrangement`` and ``ScalarSize`` add the
// derived properties (element size, lane count, byte width, isFullVector)
// consumers need without touching the core type declarations.

// MARK: - VectorArrangement / ScalarSize derived properties

public extension VectorArrangement {
    /// Element size of this arrangement: `.b` / `.h` / `.s` / `.d`.
    ///
    /// Used by the canonicalizer to emit `Vn.<size>[i]` element-subscript
    /// operands (which carry the 128-bit arrangement form by convention
    /// but render with the element-size suffix only).
    @inlinable
    @inline(__always)
    var elementSize: ScalarSize {
        switch self {
        case .b8, .b16: .b
        case .h4, .h8: .h
        case .s2, .s4: .s
        case .d1, .d2: .d
        case .q1: .q
        case .h2: .h
        }
    }

    /// Number of lanes in this arrangement (8, 16, 4, 8, 2, 4, 1, 2).
    ///
    /// For full-vector view operands, this is the operationally meaningful
    /// lane count. For `.element`-view operands, the arrangement reflects
    /// the source register's storage shape (always one of the 128-bit
    /// forms — b16/h8/s4/d2) by convention; the lane count there is
    /// NOT operationally meaningful as a per-operand attribute (the
    /// operand references a single element). Consumers must read
    /// ``VectorView`` to know which context they're in.
    @inlinable
    @inline(__always)
    var laneCount: UInt8 {
        switch self {
        case .b8: 8
        case .b16: 16
        case .h4: 4
        case .h8: 8
        case .s2: 2
        case .s4: 4
        case .d1: 1
        case .d2: 2
        case .q1: 1
        case .h2: 2
        }
    }

    /// Total byte width of the register at this arrangement: 8 for
    /// 64-bit (`.b8`, `.h4`, `.s2`, `.d1`), 16 for 128-bit (`.b16`,
    /// `.h8`, `.s4`, `.d2`).
    @inlinable
    @inline(__always)
    var byteWidth: UInt8 {
        isFullVector ? 16 : 8
    }

    /// True if this is a 128-bit (Q=1) arrangement.
    @inlinable
    @inline(__always)
    var isFullVector: Bool {
        switch self {
        case .b16, .h8, .s4, .d2, .q1: true
        case .b8, .h4, .s2, .d1, .h2: false
        }
    }
}

public extension ScalarSize {
    /// Byte width of this scalar size: 1, 2, 4, 8, 16.
    @inlinable
    @inline(__always)
    var byteWidth: UInt8 {
        switch self {
        case .b: 1
        case .h: 2
        case .s: 4
        case .d: 8
        case .q: 16
        }
    }
}

/// The canonical 128-bit `VectorArrangement` for a given element size.
/// Returns `nil` for `.q` (Q has no
/// arrangement — it's a scalar 128-bit register view, not a vector
/// arrangement).
@inlinable
@inline(__always)
public func canonicalElementArrangement(for size: ScalarSize) -> VectorArrangement? {
    switch size {
    case .b: .b16
    case .h: .h8
    case .s: .s4
    case .d: .d2
    case .q: nil
    }
}

// MARK: - Arrangement / scalar-size decoding from encoding bits

/// Decode the (size, Q) → ``VectorArrangement`` mapping used by AdvSIMD
/// vector operations (three-same, two-reg-misc, etc.) per ARM ARM tables.
/// Total over the 2-bit × 1-bit input space; reserved combinations like
/// `.1D` with multi-reg LD2/3/4 are filtered by per-class predicates on
/// the returned arrangement value.
@inlinable
@inline(__always)
@_effects(readonly)
func arrangementFromSizeQ(size: UInt8, Q: UInt8) -> VectorArrangement {
    let idx = Int(((size & 0x3) << 1) | (Q & 0x1))
    return arrangementTable[idx]
}

@usableFromInline
let arrangementTable: [VectorArrangement] = [
    .b8, .b16, .h4, .h8, .s2, .s4, .d1, .d2,
]

/// Decode the FP `ftype` (2-bit) → ``ScalarSize`` mapping per ARM ARM:
/// 00 = S, 01 = D, 11 = H (FEAT_FP16), 10 = reserved (returns nil) except
/// in the X↔V.D[1] FMOV variants — those use ftype=10 sf=1 rmode=01 as a
/// distinct encoding that the integer-conversion sub-decoder handles
/// explicitly.
@inlinable
@inline(__always)
@_effects(readonly)
func scalarSizeFromFtype(_ ftype: UInt8) -> ScalarSize? {
    switch ftype & 0x3 {
    case 0b00: .s
    case 0b01: .d
    case 0b11: .h
    default: nil
    }
}

/// Variant for callers that have already filtered ftype != 0b10
/// (reserved). Total over ftype ∈ {0b00, 0b01, 0b11}; the 0b10 input is
/// unreachable by contract and maps to .h as a sentinel.
@inlinable
@inline(__always)
@_effects(readonly)
func scalarSizeFromFtypeNonReserved(_ ftype: UInt8) -> ScalarSize {
    switch ftype & 0x3 {
    case 0b00: .s
    case 0b01: .d
    default: .h // ftype == 0b11 (callers filter 0b10).
    }
}

// MARK: - Vector operand factories

/// Build an ``Operand/vectorRegister(_:)`` operand with the full-vector view
/// (`Vn.<arrangement>`). The register index is masked to 5 bits.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpVectorOperand(_ n: UInt8, arrangement: VectorArrangement) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                      view: .full(arrangement: arrangement)))
}

/// Build an ``Operand/vectorRegister(_:)`` operand with a scalar-view (Bn /
/// Hn / Sn / Dn / Qn). The register index is masked to 5 bits.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpScalarOperand(_ n: UInt8, size: ScalarSize) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                      view: .scalar(size: size)))
}

/// Build an ``Operand/vectorRegister(_:)`` operand with the element-indexed
/// view (`Vn.<size>[i]`). The arrangement stored is the
/// canonical 128-bit form matching the element size (.b16/.h8/.s4/.d2);
/// the canonicalizer derives the element-size suffix from the arrangement.
/// Callers never pass `.q` — element-indexed operands are .b/.h/.s/.d only.
/// Build an ``Operand/vectorRegister(_:)`` operand with the element-group view
/// (`Vn.<count><type>[i]`, e.g. `Vn.4B[2]`) used by the dot-product
/// by-element forms, where the indexed operand is a `count`-element group.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpElementGroupOperand(_ n: UInt8, elementSize: ScalarSize, count: UInt8, index: UInt8) -> Operand {
    .vectorRegister(VectorRegisterRef(
        registerIndex: n & 0x1F,
        view: .elementGroup(elementSize: elementSize, count: count, index: index),
    ))
}

@inlinable
@inline(__always)
@_effects(readonly)
func simdfpElementOperand(_ n: UInt8, elementSize: ScalarSize, index: UInt8) -> Operand {
    let arrangement: VectorArrangement = switch elementSize {
    case .b: .b16
    case .h: .h8
    case .s: .s4
    default: .d2 // .d (or .q sentinel — unreachable).
    }
    return .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                             view: .element(arrangement: arrangement,
                                                            index: index)))
}

/// Bare lane-indexed operand `Vn[index]` (no element-size suffix) — the
/// FEAT_LUT table-index operand.
@inline(__always)
@_effects(readonly)
func simdfpLaneOperand(_ n: UInt8, index: UInt8) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F, view: .lane(index: index)))
}

// MARK: - Semantic register-set helpers

/// Insert SIMD register `n` (canonical-index 32+n) into the
/// ``RegisterSet``. SIMD registers are never zero-registers, so this is
/// unconditional.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpInsertingVector(_ n: UInt8, into set: RegisterSet) -> RegisterSet {
    set.inserting(RegisterRef.simd(n))
}

/// Insert GPR register `n` into the ``RegisterSet`` if not the zero-register
/// form. Mirrors the L/S `lsInsertingNonZero` pattern.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpInsertingNonZeroGPR(reg: RegisterRef, into set: RegisterSet) -> RegisterSet {
    if reg.isZeroRegister { return set }
    return set.inserting(reg)
}

/// Build a `RegisterRef` for a GPR operand at the given 5-bit register
/// field, with `<Wn|WSP>`/`<Xn|SP>` (sp-or-general) vs `<Wn|WZR>`/`<Xn|XZR>`
/// (zr-or-general) disambiguation. Mirrors `LSCommon.lsGprOperand`.
/// Note: callers in this module always pass `.x64` when `spOrGeneral` is
/// true (only the L/S base register uses SP-or-general semantics, and it
/// is always 64-bit). The WSP branch (w32 + spOrGeneral) is therefore
/// unreachable by construction — kept folded into SP via the `.sp()`
/// return path.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpGprOperand(
    encoding n: UInt8, width: RegisterWidth, spOrGeneral: Bool,
) -> RegisterRef {
    let masked = n & 0x1F
    if masked == 31 {
        if spOrGeneral {
            // Only x64 SP is reached; w32 WSP form has no caller.
            return .sp()
        }
        return width == .x64 ? RegisterRef.xzr() : RegisterRef.wzr()
    }
    return width == .x64 ? RegisterRef.x(masked) : RegisterRef.w(masked)
}

// MARK: - SIMD/FP encoding-tier predicate (for corpus-tooling pre-filter)

/// True iff the 4-byte ARM64 word `encoding` belongs to the SIMD &
/// Floating-Point in-scope encoding surface:
///   - top-level op0 ∈ {0x7, 0xF} (the SIMD/FP arithmetic/FP/conversion
///     classes that ``SIMDAndFPDecoder/decode(encoding:address:features:)``
///     dispatches), OR
///   - top-level op0 ∈ {0x4, 0x6, 0xC, 0xE} with bit[26] (V) = 1 (the
///     SIMD/FP load/store classes delegated from the integer L/S decoder
///     via ``SIMDAndFPDecoder/decodeVectorLoadStore(encoding:address:)``).
///
/// Lets corpus tooling pre-filter code buffers to SIMD/FP encodings.
@inlinable
@inline(__always)
@_effects(readonly)
@_spi(Validation)
public func isSIMDAndFPEncoding(_ encoding: UInt32) -> Bool {
    let op0 = (encoding >> 25) & 0xF
    if op0 == 0x7 || op0 == 0xF { return true }
    let V = (encoding >> 26) & 1
    if V == 1, op0 == 0x4 || op0 == 0x6 || op0 == 0xC || op0 == 0xE {
        return true
    }
    return false
}

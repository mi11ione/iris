// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

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

    /// Number of lanes in this arrangement.
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

    /// Total byte width of the register at this arrangement.
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

/// Decode the (size, Q) → ``VectorArrangement`` mapping used by AdvSIMD vector
/// operations (three-same, two-reg-misc, etc.) per ARM ARM tables.
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

/// Decode the FP `ftype` (2-bit) → ``ScalarSize`` mapping per ARM ARM.
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

/// Variant for callers that have already filtered ftype != 0b10 (reserved).
@inlinable
@inline(__always)
@_effects(readonly)
func scalarSizeFromFtypeNonReserved(_ ftype: UInt8) -> ScalarSize {
    switch ftype & 0x3 {
    case 0b00: .s
    case 0b01: .d
    default: .h
    }
}

/// Build an ``Operand/vectorRegister(_:)`` operand with the full-vector view
/// (`Vn.<arrangement>`).
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpVectorOperand(_ n: UInt8, arrangement: VectorArrangement) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                      view: .full(arrangement: arrangement)))
}

/// Build an ``Operand/vectorRegister(_:)`` operand with a scalar-view (Bn / Hn
/// / Sn / Dn / Qn).
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpScalarOperand(_ n: UInt8, size: ScalarSize) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                      view: .scalar(size: size)))
}

/// An element-group vector operand (`Vn.<count><type>[i]`, e.g. `Vn.4B[2]`),
/// used by the dot-product by-element forms where the indexed operand is a
/// `count`-element group.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpElementGroupOperand(_ n: UInt8, elementSize: ScalarSize, count: UInt8, index: UInt8) -> Operand {
    .vectorRegister(VectorRegisterRef(
        registerIndex: n & 0x1F,
        view: .elementGroup(elementSize: elementSize, count: count, index: index),
    ))
}

/// An element-indexed vector operand (`Vn.<size>[i]`).
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpElementOperand(_ n: UInt8, elementSize: ScalarSize, index: UInt8) -> Operand {
    let arrangement: VectorArrangement = switch elementSize {
    case .b: .b16
    case .h: .h8
    case .s: .s4
    default: .d2
    }
    return .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F,
                                             view: .element(arrangement: arrangement,
                                                            index: index)))
}

/// Bare lane-indexed operand `Vn[index]` (no element-size suffix).
@inline(__always)
@_effects(readonly)
func simdfpLaneOperand(_ n: UInt8, index: UInt8) -> Operand {
    .vectorRegister(VectorRegisterRef(registerIndex: n & 0x1F, view: .lane(index: index)))
}

/// Insert SIMD register `n` (canonical-index 32+n) into the ``RegisterSet``.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpInsertingVector(_ n: UInt8, into set: RegisterSet) -> RegisterSet {
    set.inserting(RegisterRef.simd(n))
}

/// Insert GPR register `n` into the ``RegisterSet`` if not the zero-register
/// form.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpInsertingNonZeroGPR(reg: RegisterRef, into set: RegisterSet) -> RegisterSet {
    if reg.isZeroRegister { return set }
    return set.inserting(reg)
}

/// Build a `RegisterRef` for a GPR operand at the given 5-bit field, with
/// sp-or-general versus zr-or-general disambiguation.
@inlinable
@inline(__always)
@_effects(readonly)
func simdfpGprOperand(
    encoding n: UInt8, width: RegisterWidth, spOrGeneral: Bool,
) -> RegisterRef {
    let masked = n & 0x1F
    if masked == 31 {
        if spOrGeneral {
            return .sp()
        }
        return width == .x64 ? RegisterRef.xzr() : RegisterRef.wzr()
    }
    return width == .x64 ? RegisterRef.x(masked) : RegisterRef.w(masked)
}

/// Whether `encoding` belongs to the SIMD & Floating-Point surface: op0 ∈
/// {0x7, 0xF}, or op0 ∈ {0x4, 0x6, 0xC, 0xE} with bit[26] (V) = 1, the
/// load/store classes delegated from the integer L/S decoder.
///
/// Lets corpus tooling pre-filter code buffers to SIMD/FP encodings.
@inlinable
@inline(__always)
@_effects(readonly)
public func isSIMDAndFPEncoding(_ encoding: UInt32) -> Bool {
    let op0 = (encoding >> 25) & 0xF
    if op0 == 0x7 || op0 == 0xF { return true }
    let V = (encoding >> 26) & 1
    if V == 1, op0 == 0x4 || op0 == 0x6 || op0 == 0xC || op0 == 0xE {
        return true
    }
    return false
}

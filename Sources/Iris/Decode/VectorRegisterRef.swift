// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// VectorRegisterRef + VectorView +
// VectorArrangement + ScalarSize. The full SIMD operand grammar:
// register-and-arrangement (Vn.8B), register-and-scalar-view (Bn/Hn/Sn/Dn/Qn),
// register-and-element-subscript (Vn.S[2]).

/// Reference to a SIMD/FP register together with the view shape used by
/// the consuming instruction.
///
/// Carried by ``Operand/vectorRegister(_:)``. The view distinguishes the
/// three SIMD operand styles: ``VectorView/full(arrangement:)`` is
/// `Vn.<arrangement>` for vector ops, ``VectorView/scalar(size:)`` is
/// the `Bn`/`Hn`/`Sn`/`Dn`/`Qn` scalar-FP and SIMD-as-scalar form, and
/// ``VectorView/element(arrangement:index:)`` is the
/// `Vn.<arrangement>[i]` element-indexed form used by DUP, INS, UMOV,
/// SMOV, and MUL by element.
@frozen
public struct VectorRegisterRef: Sendable, Hashable {
    /// SIMD register index (0..31).
    public let registerIndex: UInt8
    /// The view shape this operand uses.
    public let view: VectorView

    @inlinable
    public init(registerIndex: UInt8, view: VectorView) {
        self.registerIndex = registerIndex & 0b11111
        self.view = view
    }
}

/// SIMD operand view shape — see ``VectorRegisterRef`` for the variants.
@frozen
public enum VectorView: Sendable, Hashable {
    /// `Vn.<arrangement>` — full vector view.
    case full(arrangement: VectorArrangement)
    /// `Bn` / `Hn` / `Sn` / `Dn` / `Qn` — single-element scalar view.
    case scalar(size: ScalarSize)
    /// `Vn.<arrangement>[index]` — element-indexed view.
    case element(arrangement: VectorArrangement, index: UInt8)
    /// `Vn.<count><type>[index]` — element-group view (e.g. `Vn.4B[2]`),
    /// used by the dot-product by-element forms (SDOT/UDOT/USDOT/SUDOT/
    /// BFDOT/FDOT) where the indexed operand is a group of `count` elements.
    case elementGroup(elementSize: ScalarSize, count: UInt8, index: UInt8)
    /// `Vn[index]` — bare lane-indexed view with no element-size suffix,
    /// used by the FEAT_LUT table-index operand (e.g. `v0[3]`).
    case lane(index: UInt8)
}

/// SIMD arrangement specifier — element-size × element-count.
@frozen
public enum VectorArrangement: UInt8, Sendable, Hashable {
    /// 8 × 8-bit = 64-bit total (`8B`).
    case b8 = 0
    /// 16 × 8-bit = 128-bit total (`16B`).
    case b16 = 1
    /// 4 × 16-bit = 64-bit total (`4H`).
    case h4 = 2
    /// 8 × 16-bit = 128-bit total (`8H`).
    case h8 = 3
    /// 2 × 32-bit = 64-bit total (`2S`).
    case s2 = 4
    /// 4 × 32-bit = 128-bit total (`4S`).
    case s4 = 5
    /// 1 × 64-bit = 64-bit total (`1D`).
    case d1 = 6
    /// 2 × 64-bit = 128-bit total (`2D`).
    case d2 = 7
    /// 1 × 128-bit = 128-bit total (`1Q`) — polynomial PMULL/PMULL2 result.
    case q1 = 8
    /// 2 × 16-bit = 32-bit total (`2H`) — scalar FP16 pairwise source.
    case h2 = 9
}

/// SIMD scalar-view element size — `B` / `H` / `S` / `D` / `Q`.
@frozen
public enum ScalarSize: UInt8, Sendable, Hashable {
    /// 8-bit (`Bn`).
    case b = 0
    /// 16-bit (`Hn`).
    case h = 1
    /// 32-bit (`Sn`).
    case s = 2
    /// 64-bit (`Dn`).
    case d = 3
    /// 128-bit (`Qn`).
    case q = 4
}

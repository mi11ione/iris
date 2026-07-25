// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// multi-vector register-group operand — { Zn.T ... }. Stores the first
// register, the count (1..4; 3 exists for LD3/ST3 structured), the element
// size, and the layout. The layout is load-bearing: it disambiguates the
// physical registers (consecutive count-2 = {Zk, Zk+1}; strided count-2 =
// {Zk, Zk+8}) and drives the canonicalizer's comma-vs-range rendering.

/// A multi-vector register group operand — `{ Zn.<T>, ... }` (1 to 4
/// registers, consecutive or strided).
///
/// Carried by ``Operand/scalableVectorGroup(_:)``. The semantic reads/writes
/// are the union of the member registers' canonical indices
/// (`32 + memberIndex`); ``memberIndex(_:)`` computes each member's register
/// number from ``firstIndex``, ``count``, and ``layout``.
@frozen
public struct ScalableVectorGroup: Sendable, Hashable {
    /// First register number 0..31.
    public let firstIndex: UInt8
    /// Number of registers in the group (1...4).
    public let count: UInt8
    /// Element size shared by every register; `nil` for the size-less
    /// groups of SME2 table lookups (`{ z20, z21 }`, `{ z7 - z9 }`).
    public let element: ScalarSize?
    /// Register-numbering layout.
    public let layout: Layout
    /// A group-level lane index (`{ z16, z17 }[1]`), for the SME2 LUTI6
    /// table-pair source; `nil` for an unindexed group.
    public let elementIndex: UInt8?

    @inlinable
    @inline(__always)
    public init(
        firstIndex: UInt8, count: UInt8, element: ScalarSize?, layout: Layout,
        elementIndex: UInt8? = nil,
    ) {
        self.firstIndex = firstIndex & 0b11111 // masked (no trap)
        self.count = count
        self.element = element
        self.layout = layout
        self.elementIndex = elementIndex
    }

    /// Register-numbering layout of a multi-vector group.
    @frozen
    public enum Layout: UInt8, Sendable, Hashable {
        /// Contiguous — member `j` is `Z(first + j)`.
        case consecutive = 0
        /// Strided — member `j` is `Z(first + j·stride)`, stride `16/count`
        /// (8 for pairs, 4 for quads).
        case strided = 1
    }

    /// The register number of member `j` (0-based). Consecutive members step
    /// by 1; strided members step by `16 / count`. `j ≥ count` is treated as
    /// out of range and wrapped into the register file (no trap).
    @inlinable
    @inline(__always)
    public func memberIndex(_ j: UInt8) -> UInt8 {
        switch layout {
        case .consecutive:
            return (firstIndex &+ j) & 0b11111
        case .strided:
            let stride = count == 0 ? 1 : 16 / count
            return (firstIndex &+ j &* stride) & 0b11111
        }
    }
}

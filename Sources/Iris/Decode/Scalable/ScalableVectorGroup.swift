// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A multi-vector register group operand of 1 to 4 registers, consecutive or
/// strided. Reads and writes are the union of the members' canonical indices,
/// which ``memberIndex(_:)`` computes.
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
        self.firstIndex = firstIndex & 0b11111
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// An SME2 `ZA`-array vector operand — `za.<T>[Wv, #imm]`, optionally a range
/// `#lo:hi` and a vector-group qualifier.
///
/// ``selectRegister`` is a GPR read; ``zaMask`` is ``ZATileMask/whole``, since
/// tile-agnostic dynamic access touches the whole array.
@frozen
public struct ZAArrayVectorOperand: Sendable, Hashable {
    /// Element size of the array vectors; `nil` for the size-less whole-array
    /// view that `LDR`/`STR ZA` use, mirroring ``Operand/zaTile(index:element:)``
    /// where a nil element is the suffix-less whole `za`.
    public let element: ScalarSize?
    /// Vector-select GPR `Wv` — a semantic read.
    public let selectRegister: RegisterRef
    /// Row offset immediate.
    public let offset: UInt8
    /// High end of a range (`#lo:hi`); `nil` for a single vector.
    public let offsetHigh: UInt8?
    /// Vector-group multiplier.
    public let group: VectorGroup

    @inlinable
    @inline(__always)
    public init(
        element: ScalarSize? = nil,
        selectRegister: RegisterRef,
        offset: UInt8,
        offsetHigh: UInt8? = nil,
        group: VectorGroup = .none,
    ) {
        self.element = element
        self.selectRegister = selectRegister
        self.offset = offset
        self.offsetHigh = offsetHigh
        self.group = group
    }

    /// Vector-group multiplier on an SME2 multi-vector `ZA`-array access.
    @frozen
    public enum VectorGroup: UInt8, Sendable, Hashable {
        case none = 0
        case vgx2 = 1
        case vgx4 = 2
    }

    /// The `ZA` storage this access may touch — the whole array (tile-
    /// agnostic dynamic index).
    @inlinable
    @inline(__always)
    public var zaMask: ZATileMask {
        .whole
    }
}

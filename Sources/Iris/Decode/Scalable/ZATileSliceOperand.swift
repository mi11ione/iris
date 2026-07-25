// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ZA tile-slice operand — ZAt.<T>[Wv, #imm] (horizontal or vertical,
// with an optional slice range for SME2). The vector-select register Wv is a
// GPR (a semantic READ, restricted to W12-W15 for tile slices). Because the
// slice index derives from Wv (dynamic), the touched ZA storage is the whole
// tile (a sound over-approximation) — see `zaMask`. Effective-address /
// slice resolution needs a value analysis the caller owns.

/// An SME `ZA` tile-slice operand — `ZAt.<T>[Wv, #imm]` (horizontal or
/// vertical), or a slice range `ZAt.<T>[Wv, #lo:hi]`.
///
/// Carried by ``Operand/zaTileSlice(_:)``. ``selectRegister`` (`Wv`) is a
/// GPR read; ``zaMask`` is the whole tile's residue mask (the sound
/// decode-time ZA touch, since the slice index is dynamic).
@frozen
public struct ZATileSliceOperand: Sendable, Hashable {
    /// Tile number (bounded by ``element``: `B`:0, `H`:0-1, `S`:0-3,
    /// `D`:0-7, `Q`:0-15).
    public let tileIndex: UInt8
    /// Tile element size.
    public let element: ScalarSize
    /// Horizontal or vertical slice.
    public let direction: Direction
    /// Vector-select GPR `Wv` — a semantic read.
    public let selectRegister: RegisterRef
    /// Slice offset immediate.
    public let offset: UInt8
    /// High end of a slice range (`#lo:hi`, SME2); `nil` for a single slice.
    public let offsetHigh: UInt8?

    @inlinable
    @inline(__always)
    public init(
        tileIndex: UInt8,
        element: ScalarSize,
        direction: Direction,
        selectRegister: RegisterRef,
        offset: UInt8,
        offsetHigh: UInt8? = nil,
    ) {
        self.tileIndex = tileIndex
        self.element = element
        self.direction = direction
        self.selectRegister = selectRegister
        self.offset = offset
        self.offsetHigh = offsetHigh
    }

    /// Horizontal (`h`) or vertical (`v`) tile slice.
    @frozen
    public enum Direction: UInt8, Sendable, Hashable {
        case horizontal = 0
        case vertical = 1
    }

    /// The `ZA` storage this slice may touch — the whole tile. That is the
    /// sound over-approximation, and the only honest one at decode time:
    /// the slice index derives from a dynamic register (`Wv`), so narrowing
    /// it to a single slice needs a value analysis the caller owns.
    @inlinable
    @inline(__always)
    public var zaMask: ZATileMask {
        ZATileMask(tile: tileIndex, element: element)
    }
}

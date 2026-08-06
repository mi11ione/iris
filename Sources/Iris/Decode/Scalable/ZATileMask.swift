// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A set of SME `ZA` array positions, as a 16-bit mask over the 16 `.Q`-tile
/// positions. Two accesses share storage when ``overlaps(_:)`` is true, and masks
/// compose unions, so this is the single representation used for `ZA`.
@frozen
public struct ZATileMask: Sendable, Hashable {
    /// Bit `q` (0..15) set means `.Q`-tile position `q` (array rows
    /// `≡ q mod 16`) is in the set.
    public let bits: UInt16

    @inlinable
    @inline(__always)
    public init(bits: UInt16 = 0) {
        self.bits = bits
    }

    /// The empty set — no `ZA` storage.
    public static let none = ZATileMask(bits: 0)

    /// The whole `ZA` array — every `.Q` position. Used for the byte tile
    /// `ZA0.B`, the tile-agnostic array vector `za[Wv, #imm]`, and any
    /// access whose touched storage cannot be narrowed at decode time.
    public static let whole = ZATileMask(bits: 0xFFFF)

    /// The mask for tile `tileIndex` at element size `element`, where tile `n`
    /// occupies the `.Q` positions `{ q : q mod tileCount == n }`. An
    /// out-of-range index reduces modulo `tileCount` rather than trapping.
    @inlinable
    @inline(__always)
    public init(tile tileIndex: UInt8, element: ScalarSize) {
        let count = element.tileCount
        let base = tileIndex % count

        var mask: UInt16 = 0
        var q = base
        while q < 16 {
            mask |= UInt16(1) << q
            q &+= count
        }
        bits = mask
    }

    /// Whether `self` and `other` share any `ZA` storage — the exact
    /// architectural tile-overlap test (`a ≡ b mod min(ES_a, ES_b)`).
    @inlinable
    @inline(__always)
    public func overlaps(_ other: ZATileMask) -> Bool {
        bits & other.bits != 0
    }

    /// The union of two `ZA` position sets.
    @inlinable
    @inline(__always)
    public func union(_ other: ZATileMask) -> ZATileMask {
        ZATileMask(bits: bits | other.bits)
    }

    /// Whether the set is empty.
    @inlinable
    @inline(__always)
    public var isEmpty: Bool {
        bits == 0
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ZA-overlap model. The SME `ZA` array is one 2D byte array addressed
// as OVERLAPPING named tile views (ZA0.B; ZA0-1.H; ZA0-3.S; ZA0-7.D;
// ZA0-15.Q). `ZATileMask` represents a ZA access as a 16-bit mask over the
// 16 finest (`.Q`) tile positions: tile `ZAn.<T>` at element size `ES`
// bytes occupies rows `{ r : r mod ES == n }` (ARM ARM DDI0616 `ZAhslice`:
// row = tile + slice·ES), which is the exact union of the `mod 16` residue
// classes `{ q : q mod ES == n }`. Two accesses overlap iff their masks
// intersect. The representation is SVL-invariant: larger SVL only adds rows
// inside each `.Q` bucket, so the overlap answer needs no vector length.

/// A set of SME `ZA` array positions, as a 16-bit mask over the 16 finest
/// (`.Q`-tile) positions.
///
/// `ZATileMask` is the currency for reasoning about which `ZA` storage a
/// decoded SME instruction reads or writes. A named tile `ZAn.<T>` maps to a
/// mask via ``init(tile:element:)``; two accesses share storage iff
/// ``overlaps(_:)`` is true. The mask composes unions (multi-tile writes,
/// the whole array, dynamic tile-slice accesses), so it is the single
/// representation used by ``ScalableRegisterSet`` for `ZA` reads and writes.
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

    /// The mask for tile `tileIndex` at element size `element`.
    ///
    /// The tier at element size `element` has `element.tileCount` tiles
    /// (`B`:1, `H`:2, `S`:4, `D`:8, `Q`:16); tile `n` occupies the `.Q`
    /// positions `{ q : q mod tileCount == n }`. An out-of-range `tileIndex`
    /// is reduced modulo `tileCount` rather than trapping (the encoding
    /// field that produces it is already width-bounded; this is defensive).
    @inlinable
    @inline(__always)
    public init(tile tileIndex: UInt8, element: ScalarSize) {
        let count = element.tileCount
        let base = tileIndex % count // reduce into range, no trap

        var mask: UInt16 = 0
        var q = base
        while q < 16 {
            mask |= UInt16(1) << q
            q &+= count
        }
        bits = mask
    }

    /// True iff `self` and `other` share any `ZA` storage — the exact
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

    /// True iff no `ZA` storage is in the set.
    @inlinable
    @inline(__always)
    public var isEmpty: Bool {
        bits == 0
    }
}

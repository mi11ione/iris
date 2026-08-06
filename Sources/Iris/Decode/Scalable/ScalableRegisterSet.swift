// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Bitset over the SVE/SME state outside the GPR/SIMD mask — predicates,
/// the `ZA` residue, FFR and ZT0. The peer of ``RegisterSet`` on
/// ``InstructionRecord``, with matching set algebra so liveness treats both
/// uniformly.
@frozen
public struct ScalableRegisterSet: Sendable, Hashable {
    /// Raw 64-bit packed representation (see the file header for the layout).
    public let bits: UInt64

    @inlinable
    @inline(__always)
    public init(bits: UInt64 = 0) {
        self.bits = bits
    }

    /// The empty set.
    public static let empty = ScalableRegisterSet(bits: 0)

    @usableFromInline static let predicateFieldMask: UInt64 = 0xFFFF
    @usableFromInline static let zaShift: UInt64 = 16
    @usableFromInline static let zaFieldMask: UInt64 = 0xFFFF << 16
    @usableFromInline static let ffrBit: UInt64 = 1 << 32
    @usableFromInline static let zt0Bit: UInt64 = 1 << 33

    /// Whether predicate `index` (0..15) is in the set. Indices ≥ 16 are
    /// masked into range (no trap).
    @inlinable
    @inline(__always)
    public func containsPredicate(_ index: UInt8) -> Bool {
        (bits >> UInt64(index & 0b1111)) & 1 == 1
    }

    /// A new set with predicate `index` (0..15) added.
    @inlinable
    @inline(__always)
    public func insertingPredicate(_ index: UInt8) -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits | (UInt64(1) << UInt64(index & 0b1111)))
    }

    /// The 16-bit predicate membership field (bit `n` = P`n`).
    @inlinable
    @inline(__always)
    public var predicateMask: UInt16 {
        UInt16(truncatingIfNeeded: bits & Self.predicateFieldMask)
    }

    /// The `ZA` residue mask in this set.
    @inlinable
    @inline(__always)
    public var zaMask: ZATileMask {
        ZATileMask(bits: UInt16(truncatingIfNeeded: (bits & Self.zaFieldMask) >> Self.zaShift))
    }

    /// A new set with `za`'s positions added to the `ZA` residue mask.
    @inlinable
    @inline(__always)
    public func inserting(_ za: ZATileMask) -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits | (UInt64(za.bits) << Self.zaShift))
    }

    /// Whether FFR (the first-fault register) is in the set.
    @inlinable
    @inline(__always)
    public var containsFFR: Bool {
        bits & Self.ffrBit != 0
    }

    /// A new set with FFR added.
    @inlinable
    @inline(__always)
    public func insertingFFR() -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits | Self.ffrBit)
    }

    /// Whether ZT0 (the SME2 lookup-table register) is in the set.
    @inlinable
    @inline(__always)
    public var containsZT0: Bool {
        bits & Self.zt0Bit != 0
    }

    /// A new set with ZT0 added.
    @inlinable
    @inline(__always)
    public func insertingZT0() -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits | Self.zt0Bit)
    }

    /// Whether the set is empty.
    @inlinable
    @inline(__always)
    public var isEmpty: Bool {
        bits == 0
    }

    /// Set-union.
    @inlinable
    @inline(__always)
    public func union(_ other: ScalableRegisterSet) -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits | other.bits)
    }

    /// Set-intersection.
    @inlinable
    @inline(__always)
    public func intersection(_ other: ScalableRegisterSet) -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits & other.bits)
    }

    /// Set-difference (`self` minus `other`) — for full-def kills in liveness
    /// (`PTRUE Pd`, `/Z` `ZA` writes, non-predicated predicate writes).
    @inlinable
    @inline(__always)
    public func subtracting(_ other: ScalableRegisterSet) -> ScalableRegisterSet {
        ScalableRegisterSet(bits: bits & ~other.bits)
    }
}

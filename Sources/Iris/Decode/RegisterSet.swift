// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Bitmask over the 64 named ARM64 architectural registers — 31 GPRs, the
/// SP/XZR slot at 31, and 32 SIMD/FP at 32...63. The semantic-reads and
/// -writes carrier on ``InstructionRecord``, consumed as O(1) bit operations.
@frozen
public struct RegisterSet: Sendable, Hashable {
    /// Raw 64-bit mask. Bit `i` set means canonical-index `i` is in the set.
    public let mask: UInt64

    @inlinable
    public init(mask: UInt64 = 0) {
        self.mask = mask
    }

    /// The empty set — no register references.
    public static let empty = RegisterSet(mask: 0)

    /// Whether `reg`'s canonical-index is set in the mask. Returns false
    /// for indices >= 64 (special registers tracked elsewhere).
    @inlinable
    @inline(__always)
    public func contains(_ reg: RegisterRef) -> Bool {
        guard reg.canonicalIndex < 64 else { return false }
        return (mask >> reg.canonicalIndex) & 1 == 1
    }

    /// Set-union of `self` and `other`.
    @inlinable
    @inline(__always)
    public func union(_ other: RegisterSet) -> RegisterSet {
        RegisterSet(mask: mask | other.mask)
    }

    /// Set-intersection of `self` and `other`.
    @inlinable
    @inline(__always)
    public func intersection(_ other: RegisterSet) -> RegisterSet {
        RegisterSet(mask: mask & other.mask)
    }

    /// A new set containing `reg`'s canonical-index in addition to the
    /// current set. References whose canonical-index >= 64 are ignored.
    @inlinable
    @inline(__always)
    public func inserting(_ reg: RegisterRef) -> RegisterSet {
        guard reg.canonicalIndex < 64 else { return self }
        return RegisterSet(mask: mask | (UInt64(1) << reg.canonicalIndex))
    }

    /// A new set containing the SIMD/`Z` bit for `ref`. An SVE `Z_n`
    /// register aliases `V_n` and rides SIMD bit `32+n`, so scalable-vector
    /// participation accumulates into the same 64-bit mask as its NEON peer
    /// — dataflow over `Z`/`V` is one bitset, not two.
    @inlinable
    @inline(__always)
    public func inserting(_ ref: ScalableVectorRef) -> RegisterSet {
        RegisterSet(mask: mask | (UInt64(1) << ref.canonicalIndex))
    }

    /// A new set without `reg`'s canonical-index. References whose
    /// canonical-index >= 64 are ignored.
    @inlinable
    @inline(__always)
    public func removing(_ reg: RegisterRef) -> RegisterSet {
        guard reg.canonicalIndex < 64 else { return self }
        return RegisterSet(mask: mask & ~(UInt64(1) << reg.canonicalIndex))
    }

    /// The registers of `self` that are not in `other`.
    @inlinable
    @inline(__always)
    public func subtracting(_ other: RegisterSet) -> RegisterSet {
        RegisterSet(mask: mask & ~other.mask)
    }

    /// The registers in exactly one of `self` and `other`.
    @inlinable
    @inline(__always)
    public func symmetricDifference(_ other: RegisterSet) -> RegisterSet {
        RegisterSet(mask: mask ^ other.mask)
    }

    /// Whether every register of `self` is in `other`.
    @inlinable
    @inline(__always)
    public func isSubset(of other: RegisterSet) -> Bool {
        mask & ~other.mask == 0
    }

    /// Whether every register of `other` is in `self`.
    @inlinable
    @inline(__always)
    public func isSuperset(of other: RegisterSet) -> Bool {
        other.mask & ~mask == 0
    }

    /// Whether `self` and `other` share no register.
    @inlinable
    @inline(__always)
    public func isDisjoint(with other: RegisterSet) -> Bool {
        mask & other.mask == 0
    }

    /// Whether the set is empty.
    @inlinable
    @inline(__always)
    public var isEmpty: Bool {
        mask == 0
    }

    /// Number of registers in the set.
    @inlinable
    @inline(__always)
    public var count: Int {
        mask.nonzeroBitCount
    }
}

extension RegisterSet: Sequence {
    public typealias Element = RegisterRef

    /// Pops the lowest set bit per step: bit `i` (0…30) → `.x(i)`, bit 31 →
    /// `.sp()`, bits 32…63 → `.simd(i - 32)`. Bit 31 is SP, never XZR/WZR, since
    /// the decoders never record zero-register participation. There is no `pc`
    /// element and no `nzcv` element.
    @frozen
    public struct Iterator: IteratorProtocol, Sendable {
        @usableFromInline
        var remaining: UInt64

        @usableFromInline
        init(mask: UInt64) {
            remaining = mask
        }

        @inlinable
        public mutating func next() -> RegisterRef? {
            if remaining == 0 { return nil }
            let bit = UInt8(truncatingIfNeeded: remaining.trailingZeroBitCount)
            remaining &= remaining &- 1
            if bit < 31 { return .x(bit) }
            if bit == 31 { return .sp() }
            return .simd(bit &- 32)
        }
    }

    /// Iterate the set's registers from the lowest canonical index up;
    /// see ``Iterator`` for the element policy.
    @inlinable
    public func makeIterator() -> Iterator {
        Iterator(mask: mask)
    }

    /// Exact: equals ``count``.
    @inlinable
    public var underestimatedCount: Int {
        count
    }
}

extension RegisterSet: CustomStringConvertible {
    /// Bracketed list of the set's register names in ascending canonical-index
    /// order, e.g. `[x29, x30, sp]` or `[]` for the empty set. Each name comes
    /// from ``RegisterRef/name`` (so SIMD registers render `v0`…`v31` and the
    /// encoding-31 slot renders `sp`). A debug / logging convenience; the
    /// canonical ``Instruction/text`` does not use it.
    public var description: String {
        var parts: [String] = []
        parts.reserveCapacity(count)
        for reg in self {
            parts.append(reg.name)
        }
        return "[" + parts.joined(separator: ", ") + "]"
    }
}

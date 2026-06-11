// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// RegisterSet. A 64-bit bitset over canonical
// GPR (bits 0..31) and SIMD (bits 32..63) indices. PSTATE.NZCV is tracked
// separately via FlagEffect; FPCR/FPSR/system registers/AMX state are
// not in the bitset — they are visible through the operand stream on the
// MSR/MRS/AMX instructions that touch them.

/// Bitmask over the 64 named ARM64 architectural registers (31 GPRs +
/// SP/XZR slot at index 31 + 32 SIMD/FP at indices 32..63).
///
/// `RegisterSet` is the per-instruction semantic-reads / -writes carrier
/// on ``InstructionRecord``. Dataflow analysis (liveness, def-use,
/// reaching-definitions) consumes it as O(1) bitwise operations.
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

    /// True iff `reg`'s canonical-index is set in the mask. Returns false
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

    /// True iff every register of `self` is in `other`.
    @inlinable
    @inline(__always)
    public func isSubset(of other: RegisterSet) -> Bool {
        mask & ~other.mask == 0
    }

    /// True iff every register of `other` is in `self`.
    @inlinable
    @inline(__always)
    public func isSuperset(of other: RegisterSet) -> Bool {
        other.mask & ~mask == 0
    }

    /// True iff `self` and `other` share no register.
    @inlinable
    @inline(__always)
    public func isDisjoint(with other: RegisterSet) -> Bool {
        mask & other.mask == 0
    }

    /// True iff no register is in the set.
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

    /// Pops the lowest set bit per step, yielding each register at its
    /// architectural width: bit `i` (0…30) → `.x(i)`, bit 31 → `.sp()`,
    /// bits 32…63 → `.simd(i - 32)`.
    ///
    /// **Width policy — X-form.** The set tracks *architectural
    /// registers*; the semantic layer is independent of alias/width
    /// presentation, and W-form is a per-operand display fact the set
    /// deliberately erases. `x0`…`x30`, `sp`, `v0`…`v31` are the
    /// registers' canonical names.
    ///
    /// **Bit 31 is SP, never XZR/WZR**: the decoders never record
    /// zero-register participation (reads-as-zero, writes-discard — the
    /// zero register is not state), so bit 31 occurs only for SP/WSP
    /// participants. There is no `pc` element (PC is not a general
    /// register in ARM64 — PC-relative reads surface as operands and
    /// ``Instruction/pcRelativeTarget``) and no `nzcv` element (flags
    /// are ``FlagEffect``'s domain).
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

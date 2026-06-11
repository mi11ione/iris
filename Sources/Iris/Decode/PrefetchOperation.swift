// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// PrefetchOperation. The 5-bit `Rt` field of
// `PRFM` / `PRFUM` is a composite (operation, target, policy) tuple. The
// raw byte is preserved; named accessors decode it on demand.

/// Composite operand for the `PRFM` / `PRFUM` prefetch hint instructions.
///
/// The 5-bit raw value encodes three sub-fields: a 2-bit operation
/// (`PLD` load / `PLI` instruction-prefetch / `PST` store), a 2-bit
/// target (`L1` / `L2` / `L3`), and a 1-bit policy (`KEEP` / `STRM`).
/// Carried by ``Operand/prefetchOperation(_:)``.
@frozen
public struct PrefetchOperation: Sendable, Hashable {
    /// Raw 5-bit value, exactly as encoded in the instruction's `Rt`
    /// field.
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue & 0b11111
    }

    /// Prefetch operation (load / instruction / store).
    @inlinable
    public var operation: Operation {
        switch (rawValue >> 3) & 0b11 {
        case 0b00: .loadData
        case 0b01: .loadInstruction
        case 0b10: .storeData
        default: .reserved
        }
    }

    /// Cache level target (L1, L2, L3).
    @inlinable
    public var target: Target {
        switch (rawValue >> 1) & 0b11 {
        case 0b00: .l1
        case 0b01: .l2
        case 0b10: .l3
        default: .slc
        }
    }

    /// Cache policy (keep vs streaming).
    @inlinable
    public var policy: Policy {
        (rawValue & 0b1) == 0 ? .keep : .stream
    }

    /// Prefetch operation enumeration.
    @frozen
    public enum Operation: UInt8, Sendable, Hashable {
        /// Data prefetch for load — `PLD`.
        case loadData = 0b00
        /// Instruction prefetch — `PLI`.
        case loadInstruction = 0b01
        /// Data prefetch for store — `PST`.
        case storeData = 0b10
        /// Reserved encoding.
        case reserved = 0b11
    }

    /// Cache level target enumeration.
    @frozen
    public enum Target: UInt8, Sendable, Hashable {
        /// Level 1 cache.
        case l1 = 0b00
        /// Level 2 cache.
        case l2 = 0b01
        /// Level 3 cache.
        case l3 = 0b10
        /// System-level cache — `SLC`.
        case slc = 0b11
    }

    /// Cache policy enumeration.
    @frozen
    public enum Policy: UInt8, Sendable, Hashable {
        /// Retentive — data is expected to be used again soon.
        case keep = 0
        /// Streaming — data is expected to be used once.
        case stream = 1
    }
}

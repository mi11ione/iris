// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// SVE predicate-count pattern operand (`all`, `pow2`, `vlN`, `mulN`, …).
///
/// ``raw`` is the 5-bit field verbatim, so values outside the named set render
/// as a raw immediate; ``multiplier`` is the `mul #k` factor, 1 when absent.
@frozen
public struct SVEPredicatePattern: Sendable, Hashable {
    /// Raw 5-bit pattern field (masked into `0...31`).
    public let raw: UInt8
    /// `mul #k` multiplier on element-count forms; `1` when absent.
    public let multiplier: UInt8

    @inlinable
    @inline(__always)
    public init(raw: UInt8, multiplier: UInt8 = 1) {
        self.raw = raw & 0b11111
        self.multiplier = multiplier
    }
}

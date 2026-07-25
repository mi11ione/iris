// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE predicate pattern operand — the 5-bit constraint operand on
// PTRUE / element-count instructions (POW2, VL1..VL256, MUL3, MUL4, ALL,
// with a reserved middle range that renders as a raw immediate). The raw
// 5-bit field is stored verbatim; a `mul #k` multiplier (element-count
// forms) rides alongside. Rendering to a keyword is a later-family
// canonicalizer concern; the scalable core defines the carrier.

/// SVE predicate-count pattern operand (`all`, `pow2`, `vlN`, `mulN`, …).
///
/// Carried by ``Operand/svePredicatePattern(_:)``. ``raw`` is the 5-bit
/// pattern field verbatim (values outside the named set render as a raw
/// immediate); ``multiplier`` is the `mul #k` factor on element-count forms
/// (`1` when absent).
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

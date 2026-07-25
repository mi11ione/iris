// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// scalable-vector operand reference — Zn.<T> (with an optional element
// index for indexed forms). Carries the operand-level "dressing" (element
// size, index); the register is a bare index 0..31. Z_n aliases V_n, so its
// canonical RegisterSet index is 32+n (shared with the NEON view) — the same
// mapping RegisterRef.simd(_:) produces.

/// Reference to an SVE scalable-vector register operand — `Zn` / `Zn.<T>` /
/// `Zn.<T>[i]`.
///
/// Carried by ``Operand/scalableVector(_:)``. The register is a bare index
/// (0..31); ``element`` is the vector-length-agnostic element size (`nil`
/// for a plain `Zn`, e.g. `LDR`/`STR`/`MOVPRFX`); ``elementIndex`` is the
/// lane index on indexed forms (`nil` otherwise). Its semantic
/// read/write is ``canonicalIndex`` in ``RegisterSet`` — bit `32+n`, shared
/// with `V_n`.
@frozen
public struct ScalableVectorRef: Sendable, Hashable {
    /// Register number 0..31.
    public let registerIndex: UInt8
    /// Element size (`nil` = plain `Zn` with no suffix).
    public let element: ScalarSize?
    /// Lane index on indexed forms (`Zn.<T>[i]`); `nil` otherwise.
    public let elementIndex: UInt8?

    @inlinable
    @inline(__always)
    public init(registerIndex: UInt8, element: ScalarSize? = nil, elementIndex: UInt8? = nil) {
        self.registerIndex = registerIndex & 0b11111 // masked (no trap)
        self.element = element
        self.elementIndex = elementIndex
    }

    /// Canonical ``RegisterSet`` index — `32 + registerIndex`, shared with
    /// the NEON `V_n` view (`Z_n` and `V_n` are the same physical register).
    @inlinable
    @inline(__always)
    public var canonicalIndex: UInt8 {
        32 &+ registerIndex
    }
}

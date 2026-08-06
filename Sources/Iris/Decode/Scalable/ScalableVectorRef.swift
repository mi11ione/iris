// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Reference to an SVE scalable-vector register operand. The register is a bare
/// index (0...31); its semantic read/write is bit `32+n` in ``RegisterSet``,
/// shared with `V_n`.
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
        self.registerIndex = registerIndex & 0b11111
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

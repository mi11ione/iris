// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Encoded operand for `IC`, `DC`, `AT` and `TLBI` system instructions.
///
/// The operand spans `op1`, `CRn`, `CRm`, `op2` and sometimes `Rt`, so the
/// decoder captures the full 32-bit instruction for round-trip preservation.
/// Friendly names like `DC CIVAC` come from a separate naming table.
@frozen
public struct SystemOp: Sendable, Hashable {
    /// Raw 32-bit instruction word from which this system-op is decoded.
    /// Carries all operand bits verbatim.
    public let rawEncoding: UInt32

    @inlinable
    public init(rawEncoding: UInt32) {
        self.rawEncoding = rawEncoding
    }
}

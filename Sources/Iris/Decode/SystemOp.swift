// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SystemOp. Raw-bits wrapper for `IC` / `DC` /
// `AT` / `TLBI` operand encodings. The decoder preserves the raw 32-bit
// instruction's relevant operand bits; the human-friendly decoded form
// (e.g. "IVAU" for instruction-cache invalidate) is a downstream concern.

/// Encoded operand for `IC`, `DC`, `AT`, and `TLBI` system instructions.
///
/// The system-op operand is encoded across multiple instruction fields
/// (`op1`, `CRn`, `CRm`, `op2`, and sometimes `Rt` register reference);
/// the decoder captures the full 32-bit instruction as the operand's
/// raw value for round-trip preservation. The Branches/Exception/System
/// decoder populates this; downstream consumers that need to display
/// "DC CIVAC" friendly names consult a separate system-op naming table.
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

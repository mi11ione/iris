// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ExtendKind. Extension and size modifiers for
// extended-register and indexed-memory operands.

/// Extension kind for an extended-register or indexed-memory operand.
///
/// The four `UXT*` cases zero-extend the source register; the four `SXT*`
/// cases sign-extend. ``lsl`` is a degenerate "no extend, just shift"
/// used in some indexed addressing encodings. ``none`` represents the
/// absence of any extend modifier.
@frozen
public enum ExtendKind: UInt8, Sendable, Hashable {
    /// No extend modifier.
    case none = 0
    /// Unsigned Extend Byte — zero-extend low 8 bits to 32 or 64.
    case uxtb = 1
    /// Unsigned Extend Halfword — zero-extend low 16 bits.
    case uxth = 2
    /// Unsigned Extend Word — zero-extend low 32 bits to 64.
    case uxtw = 3
    /// Unsigned Extend Doubleword — pass through (64-bit operand).
    case uxtx = 4
    /// Signed Extend Byte — sign-extend low 8 bits.
    case sxtb = 5
    /// Signed Extend Halfword — sign-extend low 16 bits.
    case sxth = 6
    /// Signed Extend Word — sign-extend low 32 bits.
    case sxtw = 7
    /// Signed Extend Doubleword — pass through with sign-extend semantics.
    case sxtx = 8
    /// Logical Shift Left, used in `LSL` form of extended-register
    /// addressing (no extend, just shift).
    case lsl = 9
}

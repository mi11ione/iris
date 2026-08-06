// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Shift kind for a shifted-register operand or standalone shift modifier.
///
/// `.msl` is valid only inside ``Operand/shiftAmount(kind:amount:)``;
/// `.shiftedRegister(_, .msl, _)` is architecturally undefined and the decoder
/// does not type-narrow it, so consumers must check the context.
@frozen
public enum ShiftKind: UInt8, Sendable, Hashable {
    /// Logical Shift Left.
    case lsl = 0
    /// Logical Shift Right.
    case lsr = 1
    /// Arithmetic Shift Right.
    case asr = 2
    /// Rotate Right.
    case ror = 3
    /// Modified Shift Left (shift left + fill low bits with ones). Used
    /// only by AdvSIMD modified-immediate 32-bit-element shifted-ones
    /// `MOVI`/`MVNI` forms. Valid only in ``Operand/shiftAmount(kind:amount:)``.
    case msl = 4
}

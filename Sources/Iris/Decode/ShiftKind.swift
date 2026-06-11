// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ShiftKind. The shift kinds ARM64 uses
// in shifted-register operands and standalone shift-amount modifiers.
// Raw values 0..3 match the 2-bit `shift` field in the relevant
// instruction encodings; `.msl` is added for AdvSIMD modified-immediate
// shift-with-ones-fill (SIMD/FP only — never appears in a register-shift
// position).

/// Shift kind for a shifted-register operand or standalone shift-amount
/// modifier.
///
/// Carried by ``Operand/shiftedRegister(reg:shift:amount:)``,
/// ``Operand/shiftAmount(kind:amount:)``, and the addressing-mode
/// component of ``MemoryOperand``.
///
/// `.msl` (Modified Shift Left — shift left with ones-fill, used by
/// AdvSIMD modified-immediate `MOVI`/`MVNI` with 32-bit-element shifted-
/// ones forms) is valid ONLY inside ``Operand/shiftAmount(kind:amount:)``.
/// Producing `.shiftedRegister(_, .msl, _)` is undefined behaviour at the
/// architectural level; the decoder does not type-narrow this, and
/// consumers (formatters, semantic tooling) MUST verify the context.
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

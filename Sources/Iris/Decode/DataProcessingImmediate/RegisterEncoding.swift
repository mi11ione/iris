// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// RegisterRef construction helper for DPI per-instruction
// encoding-31 role rules. The encoding-31 GPR slot means
// either SP/WSP or XZR/WZR depending on the per-instruction architectural
// rule (e.g. ADD-imm Rn=31 is SP, AND-imm Rn=31 is XZR). This helper
// centralizes the decision so each per-family decoder names the form
// explicitly.

/// Architectural meaning of the GPR encoding-31 slot for a given
/// operand position. ARM ARM uses `<Xn|SP>` vs `<Xn>` syntax to mark
/// the distinction; DPI encodes that distinction as this enum.
enum RegisterEncodingForm {
    /// Encoding 31 means SP / WSP (per ARM ARM `<Xn|SP>` / `<Wn|WSP>` syntax).
    case spOrGeneral
    /// Encoding 31 means XZR / WZR (per ARM ARM `<Xn>` / `<Wn>` syntax).
    case zrOrGeneral
}

/// Build a ``RegisterRef`` for a GPR operand decoded from a 5-bit
/// register-field value. `width` is 32 (Wn) or 64 (Xn); `form` selects
/// the encoding-31 disambiguation per the instruction's architectural
/// rule.
@inline(__always)
@_effects(readonly)
func gprOperand(
    encoding n: UInt8, width: RegisterWidth, form: RegisterEncodingForm,
) -> RegisterRef {
    let masked = n & 0x1F
    if masked == 31 {
        switch form {
        case .spOrGeneral:
            return width == .x64 ? RegisterRef.sp() : RegisterRef.wsp()
        case .zrOrGeneral:
            return width == .x64 ? RegisterRef.xzr() : RegisterRef.wzr()
        }
    }
    // DPI callers pass .x64 or .w32; .vectorImplied collapses to the
    // .w branch as a deterministic fallback (no precondition trap).
    return width == .x64 ? RegisterRef.x(masked) : RegisterRef.w(masked)
}

/// Insert `reg` into the semantic read/write `set`, but skip when the
/// register is XZR/WZR. Index 31 (the only slot for both
/// SP and ZR) is recorded ONLY for SP-role; ZR-role reads/writes are
/// no-ops and would mislead downstream dataflow if included.
@inline(__always)
@_effects(readonly)
func insertingNonZero(reg: RegisterRef, into set: RegisterSet) -> RegisterSet {
    if reg.isZeroRegister { return set }
    return set.inserting(reg)
}

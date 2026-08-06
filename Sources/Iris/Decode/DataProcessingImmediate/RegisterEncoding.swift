// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Architectural meaning of the GPR encoding-31 slot for a given operand
/// position.
enum RegisterEncodingForm {
    /// Encoding 31 means SP / WSP (per ARM ARM `<Xn|SP>` / `<Wn|WSP>` syntax).
    case spOrGeneral
    /// Encoding 31 means XZR / WZR (per ARM ARM `<Xn>` / `<Wn>` syntax).
    case zrOrGeneral
}

/// Build a ``RegisterRef`` for a GPR operand from a 5-bit register field.
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
    return width == .x64 ? RegisterRef.x(masked) : RegisterRef.w(masked)
}

/// Insert `reg` into the semantic read/write `set`, skipping XZR/WZR.
@inline(__always)
@_effects(readonly)
func insertingNonZero(reg: RegisterRef, into set: RegisterSet) -> RegisterSet {
    if reg.isZeroRegister { return set }
    return set.inserting(reg)
}

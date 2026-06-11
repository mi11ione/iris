// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Shared helpers used by the L/S per-class sub-decoders.
// Mirrors `DataProcessingImmediate/RegisterEncoding.swift` (the helpers
// it declares are internal to DPI's file layout and not visible here);
// this family re-declares them locally rather than widening DPI's
// helpers.

/// Encoding-31 disambiguation form for a GPR operand position (per ARM
/// ARM `<Xn|SP>` vs `<Xn>` syntax). Mirrors DPI's `RegisterEncodingForm`.
enum LSRegisterEncodingForm {
    /// Encoding 31 means SP / WSP.
    case spOrGeneral
    /// Encoding 31 means XZR / WZR.
    case zrOrGeneral
}

/// Build a ``RegisterRef`` for a GPR operand from a 5-bit register-field encoding.
@inline(__always)
@_effects(readonly)
func lsGprOperand(
    encoding n: UInt8, width: RegisterWidth, form: LSRegisterEncodingForm,
) -> RegisterRef {
    let masked = n & 0x1F
    if masked == 31 {
        switch form {
        case .spOrGeneral:
            // Every SP-capable L/S register field is 64-bit; callers pass
            // `.x64` exclusively for this form.
            return RegisterRef.sp()
        case .zrOrGeneral:
            return width == .x64 ? RegisterRef.xzr() : RegisterRef.wzr()
        }
    }
    return width == .x64 ? RegisterRef.x(masked) : RegisterRef.w(masked)
}

/// Insert `reg` into the semantic read/write `set`, skipping XZR/WZR
/// (ZR-role reads/writes are no-ops; SP-role is included).
@inline(__always)
@_effects(readonly)
func lsInsertingNonZero(reg: RegisterRef, into set: RegisterSet) -> RegisterSet {
    if reg.isZeroRegister { return set }
    return set.inserting(reg)
}

/// Sign-extend an `imm9` (9-bit) field into a signed 64-bit value.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm9(_ imm9: UInt32) -> Int64 {
    let mask: UInt32 = 0x1FF
    let value = imm9 & mask
    let signBit = (value >> 8) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}

/// Sign-extend an `imm7` (7-bit) field into a signed 64-bit value.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm7(_ imm7: UInt32) -> Int64 {
    let mask: UInt32 = 0x7F
    let value = imm7 & mask
    let signBit = (value >> 6) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}

/// Sign-extend an `imm19` (19-bit) field into a signed 64-bit value.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm19(_ imm19: UInt32) -> Int64 {
    let mask: UInt32 = 0x7FFFF
    let value = imm19 & mask
    let signBit = (value >> 18) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}

/// Sign-extend an `imm10` (10-bit) field into a signed 64-bit value.
@inline(__always)
@_effects(readonly)
func lsSignExtendImm10(_ imm10: UInt32) -> Int64 {
    let mask: UInt32 = 0x3FF
    let value = imm10 & mask
    let signBit = (value >> 9) & 1
    if signBit == 1 {
        return Int64(bitPattern: UInt64(value) | ~UInt64(mask))
    }
    return Int64(value)
}

/// L/S op0 set: bits[28:25] = x1x0 → {0x4, 0x6, 0xC, 0xE}.
/// Packed as a bitmask indexed by op0 for branch-free membership test.
/// `@usableFromInline` so `isLoadStoreEncoding` can reference it from its
/// `@inlinable` body across module boundaries.
@usableFromInline
let lsOp0Mask: UInt32 = (1 << 0x4) | (1 << 0x6) | (1 << 0xC) | (1 << 0xE)

/// True iff the 4-byte ARM64 instruction word `encoding` belongs to the
/// Loads & Stores encoding slab (op0 bits[28:25] ∈ {0x4, 0x6, 0xC, 0xE}).
/// Lets corpus tooling pre-filter code buffers to L/S encodings
/// without invoking the full dispatcher.
@inlinable
@inline(__always)
@_effects(readonly)
@_spi(Validation)
public func isLoadStoreEncoding(_ encoding: UInt32) -> Bool {
    let op0 = (encoding >> 25) & 0xF
    return (lsOp0Mask >> op0) & 1 == 1
}

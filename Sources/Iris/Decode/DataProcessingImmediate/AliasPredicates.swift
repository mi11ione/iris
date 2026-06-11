// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Alias-precedence helpers shared across families.
// Ports of LLVM's `isMOVZMovAlias` / `isMOVNMovAlias` /
// `isAnyMOVWMovAlias`. The ORR-bitmask → MOV alias is gated by these
// predicates: MOV (bitmask) only applies when the decoded immediate is
// NOT also representable as MOVZ/MOVN — otherwise llvm-mc renders the
// raw `orr Rd, xzr, #imm` (or `movz` etc.) instead.

enum AliasPredicates {
    /// MOVZ hw-shift candidates for 64-bit registers (lifted out of
    /// ``isMOVZRepresentable(_:regSize:)`` so the array isn't reallocated
    /// per call).
    private static let movzShifts64: [UInt8] = [0, 16, 32, 48]
    /// MOVZ hw-shift candidates for 32-bit registers.
    private static let movzShifts32: [UInt8] = [0, 16]

    /// True iff `value` (within the regsize-bit window) could be
    /// produced by a MOVZ instruction at some `hw` alignment — i.e.
    /// its bits fit in a single 16-bit window aligned to 0/16/32/48
    /// (32-bit registers restricted to 0/16).
    @inline(__always)
    @_effects(readonly)
    static func isMOVZRepresentable(_ value: UInt64, regSize: UInt8) -> Bool {
        let widthMask: UInt64 = regSize == 64 ? UInt64.max : UInt64(UInt32.max)
        let masked = value & widthMask
        let shifts = regSize == 64 ? movzShifts64 : movzShifts32
        for shift in shifts {
            let outside = masked & ~(UInt64(0xFFFF) << shift)
            if (outside & widthMask) == 0 { return true }
        }
        return false
    }

    /// True iff `value` could be produced by a MOVN instruction at some
    /// `hw` alignment — equivalent to `isMOVZRepresentable(~value)`
    /// after masking to the regsize-bit window.
    @inline(__always)
    @_effects(readonly)
    static func isMOVNRepresentable(_ value: UInt64, regSize: UInt8) -> Bool {
        let widthMask: UInt64 = regSize == 64 ? UInt64.max : UInt64(UInt32.max)
        let inverted = ~value & widthMask
        return isMOVZRepresentable(inverted, regSize: regSize)
    }

    /// True iff `value` is representable by ANY MOV-wide form
    /// (`MOVZ` or `MOVN`). Used by MOV (bitmask) of ORR to gate the
    /// alias preference: when both forms are representable, llvm-mc
    /// prefers MOVZ/MOVN and does NOT apply the MOV-bitmask alias.
    @inline(__always)
    @_effects(readonly)
    static func isMOVWRepresentable(_ value: UInt64, regSize: UInt8) -> Bool {
        isMOVZRepresentable(value, regSize: regSize)
            || isMOVNRepresentable(value, regSize: regSize)
    }
}

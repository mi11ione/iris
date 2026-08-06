// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AliasPredicates {
    /// MOVZ hw-shift candidates for 64-bit registers (lifted out of
    /// ``isMOVZRepresentable(_:regSize:)`` so the array isn't reallocated per
    /// call).
    private static let movzShifts64: [UInt8] = [0, 16, 32, 48]
    /// MOVZ hw-shift candidates for 32-bit registers.
    private static let movzShifts32: [UInt8] = [0, 16]

    /// Whether `value` could be produced by a MOVZ at some `hw` alignment.
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

    /// Whether `value` could be produced by a MOVN instruction at some `hw`
    /// alignment.
    @inline(__always)
    @_effects(readonly)
    static func isMOVNRepresentable(_ value: UInt64, regSize: UInt8) -> Bool {
        let widthMask: UInt64 = regSize == 64 ? UInt64.max : UInt64(UInt32.max)
        let inverted = ~value & widthMask
        return isMOVZRepresentable(inverted, regSize: regSize)
    }

    /// Whether `value` is representable by any MOV-wide form.
    @inline(__always)
    @_effects(readonly)
    static func isMOVWRepresentable(_ value: UInt64, regSize: UInt8) -> Bool {
        isMOVZRepresentable(value, regSize: regSize)
            || isMOVNRepresentable(value, regSize: regSize)
    }
}

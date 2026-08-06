// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is an SVE/SVE2 floating-point instruction owned by SVE-FP.
/// Safe on any 32-bit word, since it re-checks `op0` itself; out-of-scope
/// op0=2 words return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEFloatingPointEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    switch (encoding >> 24) & 0xFF {
    case 0x64, 0x65:
        return true
    case 0x04:
        return (encoding & 0xFF2E_E000) == 0x040C_A000
            || (encoding & 0xFF20_FC00) == 0x0420_B000
            || (encoding & 0xFF3F_FC00) == 0x0420_B800
    case 0x05:
        return (encoding & 0xFF30_E000) == 0x0510_C000
    case 0x25:
        return (encoding & 0xFF3F_E000) == 0x2539_C000
    default:
        return false
    }
}

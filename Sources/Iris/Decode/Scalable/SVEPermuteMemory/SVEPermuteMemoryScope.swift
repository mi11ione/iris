// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is an SVE/SVE2 permute, memory or crypto instruction
/// owned by SVE-permute/memory. Safe on any 32-bit word, since it re-checks
/// `op0` itself; out-of-scope op0=2 words return `false`.
@inline(__always)
@_effects(readonly)
public func isSVEPermuteMemoryCryptoEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    if encoding & 0x8000_0000 != 0 { return true }
    switch (encoding >> 24) & 0xFF {
    case 0x05:
        return !isSVEPredicateControlEncoding(encoding)
            && !isSVEIntegerEncoding(encoding)
            && !isSVEFloatingPointEncoding(encoding)
    case 0x44:
        return (encoding & 0xFF20_E000) == 0x4400_E000
    case 0x45:
        return isSVE2CryptoOrLUT(encoding)
    default:
        return false
    }
}

/// The 0x45 crypto / LUT cluster (AES/SM4/RAX1/multi-vector-PMULL/LUTI2/4)
/// that SVE-integer excludes and SVE-permute/memory owns.
@inline(__always)
@_effects(readonly)
func isSVE2CryptoOrLUT(_ e: UInt32) -> Bool {
    (e >> 21) & 1 == 1 && (e >> 13) & 1 == 1 && (e >> 15) & 1 == 1
        && ((e >> 22) & 1 == 1 || (e >> 14) & 1 == 1 || (e >> 12) & 1 == 1 || (e >> 11) & 1 == 1)
}

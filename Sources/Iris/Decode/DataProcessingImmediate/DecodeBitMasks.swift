// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ARM ARM §J1.4 DecodeBitMasks port. Direct bit-math
// translation of LLVM's `decodeLogicalImmediate` /
// `isValidDecodeLogicalImmediate` (AArch64AddressingModes.h). Used by
// LogicalImmDecode.swift to decode the (N, immr, imms) triple into the
// concrete bitmask value AND/ORR/EOR/ANDS imm encodes.
//
// The choice of direct bit-math over a precomputed lookup table is
// deliberate: direct math is ~30
// instructions, no static memory cost, matches LLVM's production
// behavior, and avoids any table-vs-source drift.

enum DecodeBitMasks {
    /// Validate and decode a logical-immediate (N, imms, immr, regSize)
    /// triple per ARM ARM §J1.4. Returns the decoded value or `nil`
    /// when the encoding is reserved (per LLVM `isValidDecodeLogicalImmediate`:
    /// 32-bit requires N=0; `len = HighestSetBit((N<<6)|~imms)` must be
    /// at least 1, excluding the all-bits-set pattern; and `S = imms & (size-1)`
    /// must not equal `size-1`, excluding the all-ones-element pattern).
    @inline(__always)
    @_effects(readonly)
    static func decode(
        n: UInt8, imms: UInt8, immr: UInt8, regSize: UInt8,
    ) -> UInt64? {
        if regSize == 32, n != 0 { return nil }

        // UInt32 lets `.leadingZeroBitCount` produce a meaningful len (≤31) for the 7-bit combined value.
        let combined = (UInt32(n) << 6) | (UInt32(~imms) & 0x3F)
        if combined == 0 { return nil }
        let len = 31 - Int(combined.leadingZeroBitCount)
        if len < 1 { return nil }

        let size = UInt32(1) << UInt32(len) // 2, 4, 8, 16, 32, 64
        let levels: UInt32 = size &- 1
        let S = UInt32(imms) & levels
        if S == levels { return nil } // all-ones element reserved
        let R = UInt32(immr) & levels

        // Base pattern: (S+1) ones in the low (S+1) bits of an `size`-wide element.
        let basePattern: UInt64 = (UInt64(1) << (S &+ 1)) &- 1
        let rotated: UInt64 = rotateRightInElement(basePattern, by: R, elementSize: size)

        // Replicate to fill regSize bits.
        var element: UInt64 = rotated
        var width: UInt32 = size
        while width < UInt32(regSize) {
            element |= element << width
            width &*= 2
        }
        if regSize == 32 { element &= 0xFFFF_FFFF }
        return element
    }

    /// Rotate the low `elementSize` bits of `value` right by `R`, leaving high bits zero.
    @inline(__always)
    @_effects(readonly)
    static func rotateRightInElement(
        _ value: UInt64, by R: UInt32, elementSize: UInt32,
    ) -> UInt64 {
        let elementMask: UInt64 = elementSize == 64
            ? UInt64.max
            : ((UInt64(1) << elementSize) &- 1)
        let v = value & elementMask
        if R == 0 { return v }
        let lo = v >> R
        let hi = (v & ((UInt64(1) << R) &- 1)) << (elementSize &- R)
        return (lo | hi) & elementMask
    }
}

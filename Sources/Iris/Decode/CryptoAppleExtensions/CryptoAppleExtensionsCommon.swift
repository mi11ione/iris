// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Mask matching the AMX magic encoding `0x00201000 | (opcode<<5) | operand`.
@inlinable
var amxMagicMask: UInt32 {
    0xFFFF_FC00
}

/// AMX base encoding value.
@inlinable
var amxMagicValue: UInt32 {
    0x0020_1000
}

/// Whether the 32-bit encoding matches the AMX magic mask.
@inlinable
public func isAMXEncoding(_ encoding: UInt32) -> Bool {
    (encoding & amxMagicMask) == amxMagicValue
}

/// Whether the encoding is in the SME region of `op0=0b0000` — `op0=0`
/// with bit31=1. The architectural SME tier shares `op0=0` with Apple AMX
/// (recognised by ``isAMXEncoding(_:)``, a disjoint magic-mask match) and
/// UDF (`bits[31:16]==0`, handled before family dispatch).
@inlinable
public func isSMEEncoding(_ encoding: UInt32) -> Bool {
    (encoding & 0x9E00_0000) == 0x8000_0000
}

/// Whether the encoding is a crypto / PAC / MTE / AMX row owned by the
/// crypto/Apple-extensions decoders. Conservative — it matches every pattern
/// those decoders might claim, and they arbitrate validity — so corpus tooling
/// can gate which words flow to the oracle.
@inlinable
public func isCryptoPACMTEEncoding(_ encoding: UInt32) -> Bool {
    isCryptoEncoding(encoding)
        || isPACStandaloneEncoding(encoding)
        || isMTEEncoding(encoding)
}

/// Whether the encoding lies in any crypto row — AES, SHA-1/256, SHA-3,
/// SHA-512, SM3 or SM4. The per-row masks mirror the decoder's prefix checks;
/// a top-byte-only check would over-include the AdvSIMD instructions sharing
/// those prefixes and produce false-positive harvest rows.
@inlinable
public func isCryptoEncoding(_ encoding: UInt32) -> Bool {
    isAESRow(encoding) || isSHA1OrSHA256Row(encoding) || isSHA3SHA512SMRow(encoding)
}

/// AES row prefix: bits[31:16] = 0x4E28 fixed, bits[11:10] = 10 fixed.
@inlinable
public func isAESRow(_ encoding: UInt32) -> Bool {
    (encoding & 0xFFFF_0C00) == 0x4E28_0800
}

/// SHA-1 / SHA-256 row prefixes — 3-register or 2-register form.
@inlinable
public func isSHA1OrSHA256Row(_ encoding: UInt32) -> Bool {
    if (encoding & 0xFFE0_8C00) == 0x5E00_0000 { return true }
    if (encoding & 0xFFFF_0C00) == 0x5E28_0800 { return true }
    return false
}

/// SHA-3 / SHA-512 / SM3 / SM4 row prefix: top byte 0xCE plus bits[23:21] ∈
/// {000, 001, 010, 011, 100, 110}. Bit 31 = 1 puts 0xCE outside the AdvSIMD
/// space, so the only false-positive risk is bits[23:21] ∈ {101, 111}, which
/// are reserved across all crypto rows and rejected here.
@inlinable
public func isSHA3SHA512SMRow(_ encoding: UInt32) -> Bool {
    let topByte = (encoding >> 24) & 0xFF
    if topByte != 0xCE { return false }
    let bits23_21 = (encoding >> 21) & 0x7
    return bits23_21 != 0b101 && bits23_21 != 0b111
}

/// Whether the encoding lies in the DPR 1-source PAC standalone row.
///
/// Prefix: bits[31:21] = `1101 1010 110`, bits[20:16] = `00001`, S = 0,
/// opc6 ∈ {0b000000…0b010001}.
@inlinable
public func isPACOneSourceEncoding(_ encoding: UInt32) -> Bool {
    let topPrefix = encoding & 0xFFE0_0000
    if topPrefix != 0xDAC0_0000 { return false }
    let opcode2 = (encoding >> 16) & 0x1F
    if opcode2 != 0b00001 { return false }
    let opc6 = (encoding >> 10) & 0x3F
    return opc6 <= 0b010001
}

/// Whether the encoding is PACGA (DPR 2-source row).
@inlinable
public func isPACGAEncoding(_ encoding: UInt32) -> Bool {
    let masked = encoding & 0xFFE0_FC00
    return masked == 0x9AC0_3000
}

/// Whether the encoding is a PAC standalone (1-source or PACGA).
@inlinable
public func isPACStandaloneEncoding(_ encoding: UInt32) -> Bool {
    isPACOneSourceEncoding(encoding) || isPACGAEncoding(encoding)
}

/// Whether the encoding is one of ADDG / SUBG in the DPI tier.
///
/// Row prefix: bit[31] = 1 (sf), bit[29] = 0, bits[28:23] = `100011`,
/// bits[22] = 0; ADDG: bit[30] = 0; SUBG: bit[30] = 1.
@inlinable
public func isMTEAddSubGEncoding(_ encoding: UInt32) -> Bool {
    (encoding & 0x9FC0_0000) == 0x9180_0000
}

/// Whether the encoding is IRG / GMI / SUBP / SUBPS in the DPR 2-source row.
///
/// Prefix: sf = 1, bit 30 = 0, bits[28:21] = `11010110`, opc6 ∈ {`000000`,
/// `000100`, `000101`}; bit 29 is S, set only for SUBPS.
@inlinable
public func isMTEDataProcessingRegisterEncoding(_ encoding: UInt32) -> Bool {
    let topMask: UInt32 = 0xDFE0_0000
    let topMatch: UInt32 = 0x9AC0_0000
    if (encoding & topMask) != topMatch { return false }
    let opc6 = (encoding >> 10) & 0x3F
    return opc6 == 0b000000 || opc6 == 0b000100 || opc6 == 0b000101
}

/// Whether the encoding is an L/S MTE op (LDG / STG / ST2G / STZG / STZ2G /
/// LDGM / STGM / STZGM).
///
/// Prefix only — bits[31:24] = `0xD9`, bit 21 = 1; the decoder arbitrates the
/// exact (opc1, op2) values.
@inlinable
public func isMTELoadStoreEncoding(_ encoding: UInt32) -> Bool {
    let topByte = (encoding >> 24) & 0xFF
    if topByte != 0xD9 { return false }
    return ((encoding >> 21) & 1) == 1
}

/// Whether the encoding is any MTE op (DPI, DPR, or L/S).
@inlinable
public func isMTEEncoding(_ encoding: UInt32) -> Bool {
    isMTEAddSubGEncoding(encoding)
        || isMTEDataProcessingRegisterEncoding(encoding)
        || isMTELoadStoreEncoding(encoding)
}

/// Sign-extend a 9-bit two's-complement value to Int64. Used by the L/S
/// MTE imm9 (range −256…255, pre-multiplication by 16 for tag-granule
/// scaling).
@inlinable
public func signExtend9(_ value: UInt32) -> Int64 {
    let mask: UInt32 = 0x1FF
    let v = value & mask
    return (v & 0x100) != 0
        ? Int64(Int32(bitPattern: v | 0xFFFF_FE00))
        : Int64(v)
}

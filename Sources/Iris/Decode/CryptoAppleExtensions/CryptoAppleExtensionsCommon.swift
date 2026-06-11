// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Crypto/Apple-extensions shared helpers: bit-extraction utilities and
// in-scope predicates used by the crypto / PAC / MTE / AMX decoders plus
// corpus tooling, which uses these `public` free functions
// (its in-scope predicate routes any potential crypto/PAC/MTE/AMX
// encoding to llvm-mc for oracle disassembly).

/// Mask matching the AMX magic encoding `0x00201000 | (opcode<<5) | operand`.
/// `(encoding & amxMagicMask) == amxMagicValue` recognises every AMX word.
/// Internal: consumers test through `isAMXEncoding(_:)`; `@inlinable`
/// keeps the constant foldable into the predicate's inlined body.
@inlinable
var amxMagicMask: UInt32 {
    0xFFFF_FC00
}

/// AMX base encoding value — the fixed bits of every AMX instruction.
@inlinable
var amxMagicValue: UInt32 {
    0x0020_1000
}

/// True iff the 32-bit encoding matches the AMX magic mask.
@inlinable
@_spi(Validation)
public func isAMXEncoding(_ encoding: UInt32) -> Bool {
    (encoding & amxMagicMask) == amxMagicValue
}

/// True iff the encoding is a crypto / PAC / MTE / AMX row owned by the
/// crypto/Apple-extensions decoders.
/// Conservative: matches every bit-pattern those decoders MIGHT decode;
/// the decoders themselves arbitrate whether the encoding is valid.
/// Lets corpus tooling gate which words flow into the
/// crypto/PAC/MTE/AMX corpus for oracle disassembly.
@inlinable
@_spi(Validation)
public func isCryptoPACMTEEncoding(_ encoding: UInt32) -> Bool {
    isCryptoEncoding(encoding)
        || isPACStandaloneEncoding(encoding)
        || isMTEEncoding(encoding)
}

// MARK: - Crypto row predicates

/// True iff the encoding lies in any crypto row — AES, SHA-1/256
/// (3-register or 2-register form), SHA-3 / SHA-512 / SM3 / SM4. The
/// per-row masks here mirror the prefix checks the decoder uses; a
/// top-byte-only check (matching every 0x4E / 0x5E / 0xCE encoding)
/// would over-include AdvSIMD vector instructions that share those
/// prefixes and produce false-positive harvest rows.
@inlinable
@_spi(Validation)
public func isCryptoEncoding(_ encoding: UInt32) -> Bool {
    isAESRow(encoding) || isSHA1OrSHA256Row(encoding) || isSHA3SHA512SMRow(encoding)
}

/// AES row prefix: bits[31:16] = 0x4E28 fixed, bits[11:10] = 10 fixed.
@inlinable
@_spi(Validation)
public func isAESRow(_ encoding: UInt32) -> Bool {
    (encoding & 0xFFFF_0C00) == 0x4E28_0800
}

/// SHA-1 / SHA-256 row prefixes — 3-register or 2-register form.
@inlinable
@_spi(Validation)
public func isSHA1OrSHA256Row(_ encoding: UInt32) -> Bool {
    // 3-register: bits[31:21] = `0101 1110 000`, bit 15 = 0,
    // bits[11:10] = 00.
    if (encoding & 0xFFE0_8C00) == 0x5E00_0000 { return true }
    // 2-register: bits[31:16] = 0x5E28, bits[11:10] = 10.
    if (encoding & 0xFFFF_0C00) == 0x5E28_0800 { return true }
    return false
}

/// SHA-3 / SHA-512 / SM3 / SM4 row prefix: top byte 0xCE plus
/// bits[23:21] ∈ {000, 001, 010, 011, 100, 110}. The 0xCE top byte
/// has bit 31 = 1 which is outside the AdvSIMD encoding space, so the
/// only false-positive risk is bits[23:21] ∈ {101, 111} which are
/// reserved across all crypto rows (rejected here, decoded as
/// UNDEFINED downstream).
@inlinable
@_spi(Validation)
public func isSHA3SHA512SMRow(_ encoding: UInt32) -> Bool {
    let topByte = (encoding >> 24) & 0xFF
    if topByte != 0xCE { return false }
    let bits23_21 = (encoding >> 21) & 0x7
    return bits23_21 != 0b101 && bits23_21 != 0b111
}

// MARK: - PAC standalone row predicates

/// True iff the encoding lies in the DPR 1-source PAC standalone row
/// (PACIA/B/DA/DB, AUTIA/B/DA/DB, PACIZA/B/DZA/DZB, AUTIZA/B/DZA/DZB,
/// XPACI, XPACD).
///
/// Row prefix: bits[31:21] = `1101 1010 110`, bits[20:16] = `00001`,
/// S = 0 (bit 29 = 0), opc6 ∈ {0b000000…0b010001}.
@inlinable
@_spi(Validation)
public func isPACOneSourceEncoding(_ encoding: UInt32) -> Bool {
    // bits[31:21] = 1101_1010_110 = 0xDAC top-shifted; this 11-bit
    // prefix already pins bit 29 (S) to 0, so no separate S check is
    // needed below.
    let topPrefix = encoding & 0xFFE0_0000
    if topPrefix != 0xDAC0_0000 { return false }
    let opcode2 = (encoding >> 16) & 0x1F // bits[20:16]
    if opcode2 != 0b00001 { return false }
    let opc6 = (encoding >> 10) & 0x3F
    return opc6 <= 0b010001
}

/// True iff the encoding is PACGA (DPR 2-source row).
@inlinable
@_spi(Validation)
public func isPACGAEncoding(_ encoding: UInt32) -> Bool {
    // sf=1, S=0, prefix bits[31:21] = `1001 1010 110`,
    // opc6 (bits[15:10]) = `001100`.
    let masked = encoding & 0xFFE0_FC00 // bits[31:21] | bits[15:10]
    return masked == 0x9AC0_3000
}

/// True iff the encoding is a PAC standalone (1-source or PACGA).
@inlinable
@_spi(Validation)
public func isPACStandaloneEncoding(_ encoding: UInt32) -> Bool {
    isPACOneSourceEncoding(encoding) || isPACGAEncoding(encoding)
}

// MARK: - MTE row predicates

/// True iff the encoding is one of ADDG / SUBG in the DPI tier.
///
/// Row prefix: bit[31] = 1 (sf), bit[29] = 0, bits[28:23] = `100011`,
/// bits[22] = 0; ADDG: bit[30] = 0; SUBG: bit[30] = 1.
@inlinable
@_spi(Validation)
public func isMTEAddSubGEncoding(_ encoding: UInt32) -> Bool {
    (encoding & 0x9F80_0000) == 0x9180_0000
}

/// True iff the encoding is one of IRG / GMI / SUBP / SUBPS in the DPR
/// 2-source row.
///
/// Row prefix: sf = 1 (bit 31), bit 30 = 0, bits[28:21] = `11010110`,
/// opc6 (bits[15:10]) ∈ {`000000`, `000100`, `000101`}; bit 29 = S
/// (0 for IRG/GMI/SUBP; 1 for SUBPS).
@inlinable
@_spi(Validation)
public func isMTEDataProcessingRegisterEncoding(_ encoding: UInt32) -> Bool {
    // Match bit[31]=1, bit[30]=0, bits[28:21]=11010110.
    let topMask: UInt32 = 0xDFE0_0000
    let topMatch: UInt32 = 0x9AC0_0000
    if (encoding & topMask) != topMatch { return false }
    let opc6 = (encoding >> 10) & 0x3F
    return opc6 == 0b000000 || opc6 == 0b000100 || opc6 == 0b000101
}

/// True iff the encoding is one of the L/S MTE ops (LDG / STG / ST2G /
/// STZG / STZ2G / LDGM / STGM / STZGM).
///
/// Row prefix: bits[31:24] = `11011001` (`0xD9`), bit 21 = 1. This is a
/// prefix check only — the decoder arbitrates the exact (opc1, op2)
/// values when it claims or rejects the word.
@inlinable
@_spi(Validation)
public func isMTELoadStoreEncoding(_ encoding: UInt32) -> Bool {
    let topByte = (encoding >> 24) & 0xFF
    if topByte != 0xD9 { return false }
    return ((encoding >> 21) & 1) == 1
}

/// True iff the encoding is any MTE op (DPI, DPR, or L/S).
@inlinable
@_spi(Validation)
public func isMTEEncoding(_ encoding: UInt32) -> Bool {
    isMTEAddSubGEncoding(encoding)
        || isMTEDataProcessingRegisterEncoding(encoding)
        || isMTELoadStoreEncoding(encoding)
}

// MARK: - Bit utilities

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

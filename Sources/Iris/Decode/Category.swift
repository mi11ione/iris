// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Encoding-family attribution for a decoded instruction — the decoder's
/// primary provenance witness. Sentinel records take ``undefined``,
/// ``dataInCodeMarker`` or ``truncatedTail``; family-emitted records take one
/// of the rest.
@frozen
public enum Category: UInt8, Sendable, Hashable {
    /// Reserved/unallocated encoding, or `op0` with no registered family
    /// decoder. Raw `encoding` preserved.
    case undefined = 0

    /// Word falls inside a caller-provided data-in-code span (loader-level
    /// knowledge, e.g. `LC_DATA_IN_CODE`); bytes are data, not instructions.
    case dataInCodeMarker = 1

    /// Residual 1, 2, or 3 bytes at the buffer end when its length is not a
    /// multiple of 4. Residual bytes packed into `encoding` LE-low.
    case truncatedTail = 2

    /// Data Processing — Immediate.
    case dataProcessingImmediate = 3

    /// Branches, Exception-Generating, System.
    case branchesExceptionSystem = 4

    /// Data Processing — Register.
    case dataProcessingRegister = 5

    /// Loads & Stores.
    case loadsAndStores = 6

    /// SIMD & Floating-Point.
    case simdAndFP = 7

    /// ARM64E standalone Pointer Authentication.
    case pointerAuthentication = 8

    /// Cryptographic extensions (AES, SHA-1/256/3/512, SM3, SM4).
    case crypto = 9

    /// Apple AMX matrix coprocessor.
    case amx = 10

    /// Memory Tagging Extension (MTE).
    case memoryTagging = 11

    /// Scalable Vector Extension (SVE / SVE2) — the `op0=0b0010` tier.
    case sve = 12

    /// Scalable Matrix Extension (SME / SME2) — the `op0=0b0000`, bit31=1
    /// region.
    case sme = 13
}

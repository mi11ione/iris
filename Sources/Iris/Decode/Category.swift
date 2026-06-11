// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Category. Encodes the encoding-family
// attribution at decode time. Decoder sentinels are 0..2; family
// categories 3..11 are populated by the family decoders (they all
// already have a slot here; this file declares the full enum).

/// Encoding-family attribution for a decoded instruction.
///
/// `Category` is the decoder core's primary provenance witness.
/// Sentinel records use one of ``undefined``,
/// ``dataInCodeMarker``, ``truncatedTail``. Family-emitted records use
/// one of the remaining cases.
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
}

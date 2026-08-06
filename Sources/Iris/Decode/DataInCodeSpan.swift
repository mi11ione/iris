// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A caller-provided span of bytes inside a code buffer that is not
/// instructions — a jump table or embedded data slab.
///
/// Loader-level knowledge unrecoverable from bytes alone, so the decoder
/// takes it from the caller and marks the covered words as data. `offset`
/// counts from the start of the decoded buffer.
@frozen
public struct DataInCodeSpan: Sendable, Hashable {
    /// Byte offset of the span's first byte, measured from the start of
    /// the decoded buffer.
    public let offset: UInt64
    /// Span length in bytes.
    public let length: UInt64
    /// Span kind.
    public let kind: Kind

    @inlinable
    public init(offset: UInt64, length: UInt64, kind: Kind) {
        self.offset = offset
        self.length = length
        self.kind = kind
    }

    /// Span-kind tag, mirroring the `data_in_code_entry.kind` values
    /// defined in `<mach-o/loader.h>`; any other value round-trips
    /// through ``unknown(rawValue:)``.
    @frozen
    public enum Kind: Sendable, Hashable {
        /// `DICE_KIND_DATA` (0x0001) — raw data embedded in code.
        case data
        /// `DICE_KIND_JUMP_TABLE8` (0x0002) — 8-bit-element jump table.
        case jumpTable8
        /// `DICE_KIND_JUMP_TABLE16` (0x0003) — 16-bit-element jump table.
        case jumpTable16
        /// `DICE_KIND_JUMP_TABLE32` (0x0004) — 32-bit-element jump table.
        case jumpTable32
        /// `DICE_KIND_ABS_JUMP_TABLE32` (0x0005) — absolute 32-bit jump table.
        case absoluteJumpTable32
        /// Any other 16-bit value, preserved for round-trip.
        case unknown(rawValue: UInt16)

        /// The `data_in_code_entry.kind` 16-bit value.
        @inlinable
        public var rawValue: UInt16 {
            switch self {
            case .data: 0x0001
            case .jumpTable8: 0x0002
            case .jumpTable16: 0x0003
            case .jumpTable32: 0x0004
            case .absoluteJumpTable32: 0x0005
            case let .unknown(raw): raw
            }
        }

        /// Construct from a `data_in_code_entry.kind` 16-bit value.
        @inlinable
        public init(rawValue: UInt16) {
            switch rawValue {
            case 0x0001: self = .data
            case 0x0002: self = .jumpTable8
            case 0x0003: self = .jumpTable16
            case 0x0004: self = .jumpTable32
            case 0x0005: self = .absoluteJumpTable32
            default: self = .unknown(rawValue: rawValue)
            }
        }
    }
}

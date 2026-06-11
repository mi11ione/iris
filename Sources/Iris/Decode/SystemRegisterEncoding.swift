// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SystemRegisterEncoding. Packs the 5-field
// (op0, op1, CRn, CRm, op2) tuple from `MSR (register)` / `MRS` into a
// single 16-bit value. The friendly-name lookup (e.g. mapping to
// "TPIDR_EL0") belongs to the text-rendering layer, not this record type.

/// Encoded system-register identifier, as carried by `MSR (register)` and
/// `MRS`.
///
/// The five sub-fields pack into 16 bits exact: ``op0`` occupies bits 14
/// and 15 (2 bits), ``op1`` bits 11 through 13 (3 bits), ``crn`` bits 7
/// through 10 (4 bits), ``crm`` bits 3 through 6 (4 bits), and ``op2``
/// bits 0 through 2 (3 bits). Translating the tuple into a human-readable
/// name (TPIDR_EL0, CNTVCT_EL0, etc.) is a downstream concern — the
/// decoder preserves the encoding bit-for-bit.
@frozen
public struct SystemRegisterEncoding: Sendable, Hashable {
    /// Packed 16-bit form. Layout per the file-header comment.
    public let packed: UInt16

    /// Construct from the packed 16-bit form.
    @inlinable
    public init(packed: UInt16) {
        self.packed = packed
    }

    /// Construct from the five sub-fields. Each field is masked to its
    /// architectural width.
    @inlinable
    public init(op0: UInt8, op1: UInt8, crn: UInt8, crm: UInt8, op2: UInt8) {
        let packedValue = (UInt16(op0 & 0b11) << 14)
            | (UInt16(op1 & 0b111) << 11)
            | (UInt16(crn & 0b1111) << 7)
            | (UInt16(crm & 0b1111) << 3)
            | UInt16(op2 & 0b111)
        packed = packedValue
    }

    /// The 2-bit `op0` sub-field.
    @inlinable
    public var op0: UInt8 {
        UInt8((packed >> 14) & 0b11)
    }

    /// The 3-bit `op1` sub-field.
    @inlinable
    public var op1: UInt8 {
        UInt8((packed >> 11) & 0b111)
    }

    /// The 4-bit `CRn` sub-field.
    @inlinable
    public var crn: UInt8 {
        UInt8((packed >> 7) & 0b1111)
    }

    /// The 4-bit `CRm` sub-field.
    @inlinable
    public var crm: UInt8 {
        UInt8((packed >> 3) & 0b1111)
    }

    /// The 3-bit `op2` sub-field.
    @inlinable
    public var op2: UInt8 {
        UInt8(packed & 0b111)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Encoded system-register identifier for `MSR (register)` and `MRS`. The five
/// sub-fields pack into 16 bits exactly: ``op0`` at 14-15, ``op1`` at 11-13,
/// ``crn`` at 7-10, ``crm`` at 3-6, ``op2`` at 0-2. Naming the tuple is a
/// downstream concern; the decoder preserves the encoding bit-for-bit.
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

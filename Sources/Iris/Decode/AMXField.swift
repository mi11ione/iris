// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Operand payload for Apple AMX coprocessor instructions.
///
/// AMX occupies formally-unallocated encoding space and its operand grammar
/// is opcode-dependent, so the decoder carries the raw 32-bit encoding as the
/// payload and interprets sub-fields per opcode.
@frozen
public struct AMXField: Sendable, Hashable {
    /// Raw 32-bit field bits, preserved verbatim.
    public let rawBits: UInt32

    @inlinable
    public init(rawBits: UInt32) {
        self.rawBits = rawBits
    }
}

/// Opcode/operand accessors per corsix/amx's documented bit layout.
/// The full payload semantics (the 64-bit X-register value a non-set/clr
/// opcode references) is opcode-specific and chip-version-dependent; it
/// is NOT modelled because the decoder cannot see the runtime register
/// value from the instruction word alone.
public extension AMXField {
    /// AMX opcode field — bits[9:5] of the raw 32-bit encoding.
    /// Valid range 0...22 per corsix/amx. Values 23...31 are observed
    /// to fault on hardware; the decoder surfaces them as
    /// ``Mnemonic/amxUnknownOp`` with an ``Operand/amxUnknown(rawFields:)``
    /// payload (see ``isUnknownOpcode``).
    @inlinable
    var opcode: UInt8 {
        UInt8((rawBits >> 5) & 0x1F)
    }

    /// AMX operand field.
    @inlinable
    var operandField: UInt8 {
        UInt8(rawBits & 0x1F)
    }

    /// Whether ``opcode`` is the opcode-17 (`set`/`clr`) encoding, whose
    /// operand field is a 5-bit immediate rather than a GPR index.
    @inlinable
    var operandIsImmediate: Bool {
        opcode == 17
    }

    /// Whether ``opcode`` is outside the documented 0…22 range.
    @inlinable
    var isUnknownOpcode: Bool {
        opcode > 22
    }
}

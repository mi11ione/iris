// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AMXField. Raw-bits wrapper for Apple AMX
// matrix coprocessor operand payloads. AMX is Apple-private and its
// operand grammar is incomplete in public references; opcode-specific
// interpretation is layered on top. The decoder preserves the raw
// 32-bit field for round-trip.

/// Operand payload for Apple AMX coprocessor instructions.
///
/// AMX instructions occupy the formally-unallocated encoding space and
/// their operand grammar is opcode-dependent. The decoder carries the
/// raw 32-bit encoding bits as the operand's payload. Opcode-specific
/// sub-fields are interpreted when emitting an `.amxField` operand on
/// a decoded record.
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

    /// AMX operand field — bits[4:0] of the raw 32-bit encoding.
    /// Interpreted as a 5-bit immediate when ``opcode`` == 17 (0 = `set`,
    /// 1 = `clr`); for every other documented opcode it is a 5-bit
    /// GPR index (X0…X30, X31 = XZR).
    @inlinable
    var operandField: UInt8 {
        UInt8(rawBits & 0x1F)
    }

    /// True iff ``opcode`` is the opcode-17 (`set`/`clr`) encoding,
    /// whose operand field is a 5-bit immediate rather than a GPR
    /// index.
    @inlinable
    var operandIsImmediate: Bool {
        opcode == 17
    }

    /// True iff ``opcode`` is outside the documented 0…22 range.
    /// The decoder emits ``Mnemonic/amxUnknownOp`` with an
    /// ``Operand/amxUnknown(rawFields:)`` payload for these encodings;
    /// the rawFields preserve the full 32-bit word for downstream
    /// analysis.
    @inlinable
    var isUnknownOpcode: Bool {
        opcode > 22
    }
}

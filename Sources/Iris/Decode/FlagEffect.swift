// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FlagEffect. The PSTATE.NZCV read/write effect, modeled as a
// packed byte: bits 0-3 are the four flags this instruction WRITES, bits 4-7
// the four it READS. A bitmask — not an enum with an associated value — keeps
// the type one byte, so it fits the existing slot in the 40-byte
// InstructionRecord layout while expressing both which flags are written
// (exactly, including the strict-subset writers RMIF / SETF8 / SETF16, which
// preserve C) and which are consumed (ADC/SBC read C; CCMP/CCMN, the CSEL
// family, B.cond, FCSEL/FCCMP, and the flag-format converters read the
// condition). Flag-consuming is a first-class def-use signal downstream
// dataflow and control-flow analyses depend on.

/// PSTATE.NZCV read/write effect of an instruction.
///
/// Each of N, Z, C, V is tracked independently for both directions. The write
/// half records which flags the instruction sets; the read half which it
/// consumes (the condition it evaluates, or the carry it adds in). Pure
/// arithmetic/logical `S` forms, `CMP`/`CMN`/`TST`, and the FP compares write
/// all four and read none (``nzcv``); most instructions touch no flags
/// (``none``).
@frozen
public struct FlagEffect: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Writes PSTATE.N.
    public static let writesN = FlagEffect(rawValue: 1 << 0)
    /// Writes PSTATE.Z.
    public static let writesZ = FlagEffect(rawValue: 1 << 1)
    /// Writes PSTATE.C.
    public static let writesC = FlagEffect(rawValue: 1 << 2)
    /// Writes PSTATE.V.
    public static let writesV = FlagEffect(rawValue: 1 << 3)

    /// Reads PSTATE.N.
    public static let readsN = FlagEffect(rawValue: 1 << 4)
    /// Reads PSTATE.Z.
    public static let readsZ = FlagEffect(rawValue: 1 << 5)
    /// Reads PSTATE.C.
    public static let readsC = FlagEffect(rawValue: 1 << 6)
    /// Reads PSTATE.V.
    public static let readsV = FlagEffect(rawValue: 1 << 7)

    /// No flag is read or written.
    public static let none: FlagEffect = []
    /// Writes all four flags, reads none — the common "set flags" effect of
    /// the `S` arithmetic/logical forms, `CMP`/`CMN`/`TST`, and FP compares.
    public static let nzcv: FlagEffect = [.writesN, .writesZ, .writesC, .writesV]
    /// Reads all four flags (the full condition), writes none.
    public static let readsNZCV: FlagEffect = [.readsN, .readsZ, .readsC, .readsV]

    /// The write half — which of N, Z, C, V this instruction sets.
    @inlinable
    public var writtenFlags: FlagEffect {
        intersection(.nzcv)
    }

    /// The read half — which of N, Z, C, V this instruction consumes.
    @inlinable
    public var readFlags: FlagEffect {
        intersection(.readsNZCV)
    }

    /// True iff the instruction writes any condition flag.
    @inlinable
    public var writesAnyFlag: Bool {
        !writtenFlags.isEmpty
    }

    /// True iff the instruction reads any condition flag.
    @inlinable
    public var readsAnyFlag: Bool {
        !readFlags.isEmpty
    }
}

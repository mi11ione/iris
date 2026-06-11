// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// PSTATEField. The PSTATE fields accessible via
// the `MSR (immediate)` instruction. Each field's encoding is the
// (op1, op2) sub-field tuple from the MSR instruction; the decoder
// captures the canonical enum case and the raw tuple for round-trip.

/// PSTATE field selector for the `MSR (immediate)` instruction.
///
/// Carried by ``Operand/pstateField(_:)``. The cases enumerated here
/// correspond to PSTATE fields documented across ARMv8.0 through
/// ARMv9.x; ``unknown(op1:op2:)`` round-trips any field that the
/// decoder does not recognize (forward-compatibility for future
/// architecture additions).
@frozen
public enum PSTATEField: Sendable, Hashable {
    /// `SPSel` — selects between SP_EL0 and SP_ELx.
    case spSel
    /// `DAIFSet` — set the DAIF interrupt masks.
    case daifSet
    /// `DAIFClr` — clear the DAIF interrupt masks.
    case daifClr
    /// `UAO` — user access override (ARMv8.2-UAO).
    case uao
    /// `PAN` — privileged access never (ARMv8.1-PAN).
    case pan
    /// `DIT` — data-independent timing (ARMv8.4-DIT).
    case dit
    /// `TCO` — tag check override (ARMv8.5-MTE).
    case tco
    /// `SSBS` — speculative store bypass safe (ARMv8.0-SSBS).
    case ssbs
    /// `ALLINT` — all interrupts mask (ARMv8.8-NMI).
    case allInt
    /// `PM` — PMU exception mask (FEAT_SEBEP).
    case pm
    /// Any other field encoded by the (op1, op2) tuple from the MSR
    /// (immediate) instruction; preserved verbatim for round-trip.
    case unknown(op1: UInt8, op2: UInt8)
}

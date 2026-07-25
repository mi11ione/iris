// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// per-instruction scalable/streaming effect flags — the FlagEffect
// analog for the SVE/SME properties that are NOT register reads/writes.
// Kept separate from ScalableRegisterSet (whose union/intersection must not
// see these bits) so the register sets stay pure. Default-empty on every
// existing record; populated by the region decoders as they decode instructions.

/// Per-instruction scalable-execution effect flags.
///
/// `ScalableEffect` carries the SVE/SME properties a decoder classifies that
/// are not expressible as register reads/writes: whether the instruction's
/// register writes are partial (may-write vs full def), its relationship to
/// streaming mode (`PSTATE.SM`) and `ZA`-enable, and the fault class of a
/// scalable load. These are the per-instruction facts a streaming-mode or
/// dataflow analysis needs and cannot recover from the register sets alone.
/// Base-ISA records carry ``none``; the scalable region decoders set the
/// flags per instruction.
@frozen
public struct ScalableEffect: OptionSet, Sendable, Hashable {
    public let rawValue: UInt8

    @inlinable
    @inline(__always)
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// No scalable effect (base-ISA default): all register writes are full
    /// defs and no streaming-mode relationship.
    public static let none: ScalableEffect = []

    /// This instruction's register writes are PARTIAL (may-write / no strong
    /// kill) rather than full-register defs — predicated SVE writes and `ZA`
    /// tile-slice writes. A consumer must not treat a partial write as a
    /// kill. Clear = full def (the base-ISA guarantee).
    public static let partialWrite = ScalableEffect(rawValue: 1 << 0)

    /// This instruction's semantics or effective vector length depend on
    /// `PSTATE.SM` (streaming mode).
    public static let readsStreamingMode = ScalableEffect(rawValue: 1 << 1)

    /// This instruction writes `PSTATE.SM` — a streaming-mode transition
    /// (`SMSTART`/`SMSTOP` targeting `SM`).
    public static let writesStreamingMode = ScalableEffect(rawValue: 1 << 2)

    /// This instruction writes the `PSTATE.ZA` enable state
    /// (`SMSTART`/`SMSTOP` targeting `ZA` — enables and zeroes `ZA`).
    public static let writesZAEnable = ScalableEffect(rawValue: 1 << 3)

    /// This is an SVE **first-fault** load (`LDFF1*`): the first active
    /// element loads normally (may fault); subsequent elements are
    /// first-faulting — a faulting access is suppressed and recorded in the
    /// first-fault register (FFR) rather than taken. Set alongside FFR
    /// read+write in the scalable register sets.
    public static let firstFaulting = ScalableEffect(rawValue: 1 << 4)

    /// This is an SVE **non-fault** load (`LDNF1*`): no element generates a
    /// fault — every access that would fault is suppressed and recorded in the
    /// FFR. Like ``firstFaulting`` it reads+writes FFR; the two are
    /// disambiguated by which flag is set.
    public static let nonFaulting = ScalableEffect(rawValue: 1 << 5)

    /// This is an SVE **non-temporal** load or store (`LDNT1*`/`STNT1*`): a
    /// hint that the data has low temporal locality. No FFR interaction.
    ///
    public static let nonTemporal = ScalableEffect(rawValue: 1 << 6)

    // Bit 7 is reserved for a further per-instruction streaming legality
    // distinction (requires-SM=0/1, requires-ZA-enabled) that SME-core/SME2 may
    // add once real decodes exist.
}

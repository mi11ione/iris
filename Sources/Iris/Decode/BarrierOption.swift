// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// BarrierOption. The 4-bit option field for
// `DSB`, `DMB`, and (degenerate) `ISB`. Raw values match the architectural
// encoding; the reserved values (0b0000, 0b0100, 0b1000, 0b1100) make
// `init?(rawOptionBits:)` return nil — the caller is responsible for
// preserving the raw 4-bit value separately when it observes a reserved
// encoding (the BES family routes reserved DSB/DMB options to the
// instruction's `.undefined` path rather than fabricating a barrier
// kind).

/// Memory-barrier option for the `DSB`, `DMB`, and `ISB` instructions.
///
/// Carried by ``Operand/barrierOption(_:)``. The architecturally-defined
/// options cover shareability domains (outer/inner/non-shareable, full
/// system) crossed with read/write/all access types. `SY` is the default
/// for `ISB`.
@frozen
public enum BarrierOption: UInt8, Sendable, Hashable {
    /// Outer Shareable, Reads.
    case oshld = 0b0001
    /// Outer Shareable, Writes.
    case oshst = 0b0010
    /// Outer Shareable, All accesses.
    case osh = 0b0011
    /// Non-shareable, Reads.
    case nshld = 0b0101
    /// Non-shareable, Writes.
    case nshst = 0b0110
    /// Non-shareable, All accesses.
    case nsh = 0b0111
    /// Inner Shareable, Reads.
    case ishld = 0b1001
    /// Inner Shareable, Writes.
    case ishst = 0b1010
    /// Inner Shareable, All accesses.
    case ish = 0b1011
    /// Full System, Reads.
    case ld = 0b1101
    /// Full System, Writes.
    case st = 0b1110
    /// Full System, All accesses (default for `ISB`).
    case sy = 0b1111
}

public extension BarrierOption {
    /// Construct from a 4-bit option field. Returns `nil` for the
    /// reserved values (0, 0b0100, 0b1000, 0b1100). Reserved values
    /// are preserved separately by the caller for round-trip when
    /// observed in the wild.
    @inlinable
    init?(rawOptionBits: UInt8) {
        switch rawOptionBits & 0b1111 {
        case 0b0001: self = .oshld
        case 0b0010: self = .oshst
        case 0b0011: self = .osh
        case 0b0101: self = .nshld
        case 0b0110: self = .nshst
        case 0b0111: self = .nsh
        case 0b1001: self = .ishld
        case 0b1010: self = .ishst
        case 0b1011: self = .ish
        case 0b1101: self = .ld
        case 0b1110: self = .st
        case 0b1111: self = .sy
        default: return nil
        }
    }
}

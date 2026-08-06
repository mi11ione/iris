// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Memory-barrier option for `DSB`, `DMB` and `ISB`: the shareability domains
/// crossed with read/write/all access types. `SY` is the default for `ISB`.
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Optional instruction-set extensions to decode; the empty set is plain
/// ARM64, and encodings of an absent extension decode as honest UNDEFINED.
///
/// Almost nothing needs a flag — one exists only where an encoding space
/// means different things on different targets, today the ARM64E load tier
/// alone. Raw-value bits are never reused; bits 1 and 2 are retired.
@frozen
public struct Features: OptionSet, Sendable, Hashable {
    /// Raw option bits. Bits are assigned in declaration order and never
    /// reused or renumbered.
    public let rawValue: UInt64

    @inlinable
    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    /// Plain ARM64: no optional extensions. The named spelling of the
    /// empty set, so a base-ISA call site reads `features: .base` instead
    /// of the bare `features: []`. Identical in value to `[]`.
    public static let base: Features = []

    /// ARM64E pointer-authentication encodings that are unallocated on
    /// plain ARM64 (today: the LDRAA/LDRAB load tier). PAC encodings
    /// that exist on the base ISA (hint-space PACIASP and friends,
    /// BRAA/RETAA) decode regardless of this flag.
    public static let pointerAuthentication = Features(rawValue: 1 << 0)

    /// Target-flavor preset: everything an arm64e slice implies.
    /// Today identical to ``pointerAuthentication``.
    public static let arm64e: Features = .pointerAuthentication
}

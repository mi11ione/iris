// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Optional instruction-set extensions to decode. The empty set is plain
/// ARM64.
///
/// Decode is a pure function of (bytes, base address, features,
/// data-in-code spans); `Features` is the third input. Encodings that
/// belong to an extension absent from the set decode as honest UNDEFINED
/// records — never a plausible-looking wrong answer.
///
/// Raw-value bits are assigned in declaration order and are never reused
/// or renumbered, so persisted `rawValue`s stay meaningful across
/// releases. Future extensions (SME, SVE, …) arrive as new option
/// members; adding one breaks no source, no layout, and no semantics.
@frozen
public struct Features: OptionSet, Sendable, Hashable {
    /// Raw option bits. Bits are assigned in declaration order and never
    /// reused or renumbered.
    public let rawValue: UInt64

    @inlinable
    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    /// ARM64E pointer-authentication encodings that are unallocated on
    /// plain ARM64 (today: the LDRAA/LDRAB load tier). PAC encodings
    /// that exist on the base ISA (hint-space PACIASP and friends,
    /// BRAA/RETAA) decode regardless of this flag.
    public static let pointerAuthentication = Features(rawValue: 1 << 0)

    /// Target-flavor preset: everything an arm64e slice implies.
    /// Today identical to ``pointerAuthentication``.
    public static let arm64e: Features = .pointerAuthentication
}

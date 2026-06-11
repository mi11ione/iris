// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MemoryOrdering. OptionSet because acquire and
// release are independent dimensions; an acquire-release load-or-store
// pairs both.

/// Memory ordering of a memory-accessing instruction.
///
/// Most ARM64 memory instructions carry no ordering bits (relaxed access).
/// Acquire / release ordering is signaled by mnemonic suffixes (`LDAR`,
/// `STLR`, `LDAXR`, `STLXR`) and tracked here in addition to ``MemoryAccess``.
@frozen
public struct MemoryOrdering: OptionSet, Sendable, Hashable {
    /// Raw bitmask of the ordering bits.
    public let rawValue: UInt8

    @inlinable
    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Load-acquire semantics — observed prior loads/stores complete
    /// before this load takes effect, from this hart's point of view.
    public static let acquire = MemoryOrdering(rawValue: 1 << 0)

    /// Store-release semantics — subsequent loads/stores from this hart
    /// observe this store before they take effect.
    public static let release = MemoryOrdering(rawValue: 1 << 1)
}

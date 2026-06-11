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
///
/// Ordering is a property of an *access*. It qualifies the acquire/release
/// semantics of the load or store the instruction performs, so it is
/// non-empty only when ``MemoryAccess`` is non-`none`. A standalone barrier
/// (`DMB`, `DSB`, `ISB`, and the `DMB ISHLD`-style scoped forms) performs no
/// access — its ``MemoryAccess`` is `none`, so its ordering is `[]` and its
/// scope rides on the instruction's barrier-option operand, not here. Do not
/// read a barrier's reach off this set: it describes load/store ordering, not
/// fence scope.
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

extension MemoryOrdering: CustomStringConvertible {
    /// Bracketed list of the ordering names in fixed order, `[acquire]`,
    /// `[release]`, `[acquire, release]`, or `[]` for relaxed. A debug /
    /// logging convenience; the canonical assembly rendering does not use it.
    public var description: String {
        var parts: [String] = []
        if contains(.acquire) { parts.append("acquire") }
        if contains(.release) { parts.append("release") }
        return "[" + parts.joined(separator: ", ") + "]"
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Memory ordering of a memory-accessing instruction, non-empty only when
/// ``MemoryAccess`` is non-`none`. A standalone barrier performs no access, so
/// its ordering is `[]` and its scope rides on the barrier-option operand —
/// this set describes load/store ordering, never fence scope.
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

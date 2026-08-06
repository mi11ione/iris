// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Zeroing / merging qualifier on a governing predicate.
///
/// ``zeroing`` (`/Z`) sets inactive destination lanes to zero, a full write;
/// ``merging`` (`/M`) preserves them from the destination's prior value,
/// making the destination a semantic read. ``none`` is a bare predicate.
@frozen
public enum PredicateQualifier: UInt8, Sendable, Hashable {
    /// Bare predicate — no `/Z` or `/M` (a result predicate, or an
    /// unqualified governing predicate such as `SEL`'s).
    case none = 0
    /// `/Z` — zeroing: inactive destination lanes become zero.
    case zeroing = 1
    /// `/M` — merging: inactive destination lanes keep their prior value;
    /// the destination is read-modify-write.
    case merging = 2
}

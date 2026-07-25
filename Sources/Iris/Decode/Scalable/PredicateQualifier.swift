// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// governing-predicate qualifier. A predicated SVE/SME instruction's
// governing predicate carries a /Z (zeroing) or /M (merging) qualifier that
// determines the fate of inactive destination lanes — and, for /M, makes the
// destination a read-modify-write. The qualifier is a property of the opcode
// (LLVM keeps it in the instruction format, not the register); the decoder
// attaches it to the predicate operand.

/// Zeroing / merging qualifier on a governing predicate.
///
/// Carried by ``ScalablePredicateRef``. ``zeroing`` (`/Z`) sets inactive
/// destination lanes to zero (a full destination write); ``merging`` (`/M`)
/// preserves inactive destination lanes from the destination's prior value
/// (making the destination a semantic read). ``none`` is a bare governing or
/// result predicate with no qualifier.
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

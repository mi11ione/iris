// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Whether `encoding` is in the SVE-region carve SME2 owns — an `op0=0b0010`
/// word none of the four SVE scope predicates claims. The carve resolves to the
/// predicate-as-counter cells at top byte `0x25` with `b21=1`, plus their
/// unallocated holes.
@inline(__always)
@_effects(readonly)
public func isSVECounterPredicateEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    return !isSVEPredicateControlEncoding(encoding) && !isSVEIntegerEncoding(encoding)
        && !isSVEFloatingPointEncoding(encoding) && !isSVEPermuteMemoryCryptoEncoding(encoding)
}

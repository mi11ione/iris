// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SME2 scope predicate for the SVE region. The single predicate with
// three consumers (the `SVEDecoder` dispatch tail, the scalable text router,
// and the validation bridge's region routing), so decode / render / validate
// cannot drift from what SME2 owns.
//
// SME2 closes the scalable tier, so its claim is the exact complement of its
// siblings — no residue tables, no per-family exclusions. In the SME region
// (op0=0b0000, bit31=1) it owns everything `isSMECoreEncoding` does not, which
// is why that side needs no predicate of its own — the `SMEDecoder` and
// `SMEDisassembly` tails simply negate the core gate. In the SVE region
// (op0=0b0010) it owns the words all four SVE family
// predicates reject (the predicate-as-counter carve: WHILE→PN and
// predicate-pair, PEXT, PTRUE-counter, CNTP-counter, PSEL, FIRSTP/LASTP).
// Tier closure is total by construction — every op0∈{0,2} word has exactly
// one owner — and a boundary mis-draw on either side gates loudly in the
// exhaustive sweeps (spec: op0=0 in-scope 83,509,056 words, op0=2
// in-scope 5,337,088 words; both pinned as census tripwires).

/// True iff `encoding` is in the SVE-region carve SME2 owns — an `op0=0b0010`
/// word that none of the four SVE family scope predicates (SVE-predicate–SVE-permute/memory)
/// claims. The carve resolves to the predicate-as-counter cells at top byte
/// `0x25` with `b21=1` (WHILE-counter/pair, PEXT, PTRUE-counter, PSEL at
/// `b15:14=01`; CNTP-counter at `b15:14=10, b9=1`; FIRSTP/LASTP at
/// `b15:14=10, opc=001/010`) plus those cells' unallocated holes.
@inline(__always)
@_effects(readonly)
public func isSVECounterPredicateEncoding(_ encoding: UInt32) -> Bool {
    guard (encoding >> 25) & 0xF == 0b0010 else { return false }
    return !isSVEPredicateControlEncoding(encoding) && !isSVEIntegerEncoding(encoding)
        && !isSVEFloatingPointEncoding(encoding) && !isSVEPermuteMemoryCryptoEncoding(encoding)
}

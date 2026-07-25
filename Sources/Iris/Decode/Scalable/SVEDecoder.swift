// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE family decoder — registers for op0 = 0b0010 (the entire SVE / SVE2
// tier). Sub-dispatches through the family scope predicates into the region
// decoders (predicate/control, integer, floating-point, permute/memory, and
// the predicate-as-counter carve SME2 owns), which resolve the concrete
// instruction; an in-scope hole returns a well-formed UNDEFINED record
// (category .sve) from the region decoder that claims it. The five predicates
// partition op0=2 exactly — the counter carve is *defined* as the complement
// of the other four — so the tail needs no predicate of its own and the
// dispatch is total by construction.

/// The SVE / SVE2 family decoder, registered for `op0=0b0010`.
///
/// Conforms to ``FamilyDecoder`` and is registered in
/// ``FamilyDecoderSet/standard`` so
/// ``MachineCodeDecoder/dispatch(encoding:address:families:context:)`` routes
/// `op0=0b0010` encodings here; each word then reaches the region decoder
/// whose scope predicate claims it.
struct SVEDecoder: FamilyDecoder, Sendable {
    static let sveOp0Values: Set<UInt8> = [0b0010]

    init() {}

    var op0Values: Set<UInt8> {
        Self.sveOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // SVE predicate & control owns a precise slice of the tier, spanning
        // two of the coarse encoding regions — the predicate region and a
        // carve-out of the integer region — so it is gated by an exact
        // encoding predicate and intercepts first.
        if isSVEPredicateControlEncoding(encoding) {
            return SVEPredicateControlDecode.decode(encoding: encoding, address: address)
        }
        if isSVEIntegerEncoding(encoding) {
            return SVEIntegerDecode.decode(encoding: encoding, address: address)
        }
        if isSVEFloatingPointEncoding(encoding) {
            return SVEFloatingPointDecode.decode(encoding: encoding, address: address)
        }
        if isSVEPermuteMemoryCryptoEncoding(encoding) {
            return SVEPermuteMemoryDecode.decode(encoding: encoding, address: address)
        }
        // What the four predicates above leave is exactly the predicate-as-
        // counter carve SME2 owns (WHILE→PN/pair, PEXT, PTRUE-counter,
        // CNTP-counter, PSEL, FIRSTP/LASTP): `isSVECounterPredicateEncoding` is
        // *defined* as their complement over op0=2, so on this path it always
        // holds and the tail takes no test of its own. An architecturally-
        // unallocated hole inside the carve returns a well-formed UNDEFINED
        // record (category .sve) from the carve's own decoder.
        return SME2PredicateDecode.decode(encoding: encoding, address: address)
    }
}

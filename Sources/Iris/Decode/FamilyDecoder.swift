// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FamilyDecoder protocol + FamilyDecoderSet. The per-family registration
// surface the encoding families conform to. The contract: each family
// declares the `op0` values it handles and a decoder that resolves
// preferred aliases inline. Registration is internal and centralized in
// `FamilyDecoderSet.standard`; the public surface routes every decode
// through that table.

/// Per-encoding-family decoder registration surface.
///
/// Each encoding family conforms a concrete value-type `FamilyDecoder`
/// (e.g. `DataProcessingImmediateDecoder`) and is registered in
/// ``FamilyDecoderSet/standard``, the dispatch table composing every
/// shipped family.
///
/// The `decode` function returns a fully-formed ``DecodedDraft`` with
/// the preferred alias mnemonic already resolved — alias resolution is
/// inlined per encoding class inside each family decoder.
///
/// Internal contract (auditable in-module): the dispatcher's op0-slab
/// routing guarantees `decode` only ever sees encodings whose `op0` is
/// in the family's declared `op0Values`, and every declared `op0` is a
/// valid 4-bit value.
protocol FamilyDecoder: Sendable {
    /// The set of `op0` values this family handles. Must be disjoint
    /// across registered families and within 0...15.
    var op0Values: Set<UInt8> { get }

    /// Decode one 4-byte word into the family's draft form, operands
    /// inline and preferred aliases resolved.
    func decode(encoding: UInt32, address: UInt64, features: Features) -> DecodedDraft
}

/// The dispatcher's 16-element family-decoder lookup table.
///
/// Composition is centralized and fixed: ``standard`` composes every
/// shipped family. Registration in the reserved tier (`op0 ∈ {0,1,2,3}`)
/// is *allowed* — Apple's AMX coprocessor occupies parts of the
/// formally-unallocated encoding space and the AMX family decoder
/// registers there.
struct FamilyDecoderSet: Sendable {
    let table: [(any FamilyDecoder)?]

    /// Build the dispatcher table from family decoders. Every declared
    /// `op0` is a valid 4-bit value disjoint across families — the
    /// internal `FamilyDecoder` contract, auditable in-module.
    init(decoders: [any FamilyDecoder]) {
        var slots: [(any FamilyDecoder)?] = Array(repeating: nil, count: 16)
        for decoder in decoders {
            for op0 in decoder.op0Values {
                slots[Int(op0)] = decoder
            }
        }
        table = slots
    }

    /// The decoder registered for `op0`, or `nil` if none is registered
    /// (in which case the dispatcher emits an UNDEFINED draft). `op0`
    /// is masked to 4 bits, matching the dispatcher's extraction.
    @inline(__always)
    func familyForOp0(_ op0: UInt8) -> (any FamilyDecoder)? {
        table[Int(op0 & 0xF)]
    }

    /// The default dispatcher table. Composes every family decoder
    /// shipped to date. The composition is centralized here (rather
    /// than per-family extensions of `.standard`, which Swift disallows
    /// for `static let`).
    static let standard: FamilyDecoderSet = .init(decoders: [
        DataProcessingImmediateDecoder(),
        BranchesExceptionSystemDecoder(),
        DataProcessingRegisterDecoder(),
        LoadsAndStoresDecoder(),
        SIMDAndFPDecoder(),
        AMXDecoder(),
    ])
}

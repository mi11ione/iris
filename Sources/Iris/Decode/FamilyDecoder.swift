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

    /// This family's dispatcher tag. Declared by the family rather than
    /// inferred from its type, so a new family cannot be registered
    /// without the dispatcher gaining a branch for it. See ``FamilyTag``.
    var tag: FamilyTag { get }

    /// Decode one 4-byte word into the family's draft form, preferred
    /// aliases resolved. Operands are emitted into `sink` and the draft
    /// records only how many.
    func decode(
        encoding: UInt32,
        address: UInt64,
        features: Features,
        _ sink: inout OperandSink,
    ) -> DecodedDraft
}

/// Which concrete family decoder occupies a dispatcher slot.
///
/// Holding the registration as `[(any FamilyDecoder)?]` and reaching a
/// family through it costs an existential load plus a witness-table call
/// the optimizer cannot see through — once per instruction, in front of
/// the entire decode tree, and a slot *miss* loads and destroys a 40-byte
/// `Optional<any FamilyDecoder>` where a tag reads one byte. Every shipped
/// family type is a stateless empty struct, so a per-slot tag lets the
/// dispatcher call the family concretely and lets the optimizer specialize
/// through it, and the existential array is not stored at all.
///
/// Each family declares its own tag, and the dispatcher switches over this
/// enum with no `default`, so registering a family without giving the
/// dispatcher a branch for it is a compile error rather than a silent
/// UNDEFINED.
enum FamilyTag: UInt8, Sendable {
    case unregistered
    case dataProcessingImmediate
    case branchesExceptionSystem
    case loadsAndStores
    case dataProcessingRegister
    case simdAndFP
    case op0Zero
    case sve
}

/// The dispatcher's 16-element family-decoder lookup table.
///
/// Composition is centralized and fixed: ``standard`` composes every
/// shipped family. Registration in the reserved tier (`op0 ∈ {0,1,2,3}`)
/// is *allowed* — Apple's AMX coprocessor occupies parts of the
/// formally-unallocated encoding space and the AMX family decoder
/// registers there.
struct FamilyDecoderSet: Sendable {
    /// Per-`op0` concrete family identity. See ``FamilyTag``.
    let tags: [FamilyTag]

    /// Build the dispatcher table from family decoders. Every declared
    /// `op0` is a valid 4-bit value disjoint across families — the
    /// internal `FamilyDecoder` contract, auditable in-module.
    ///
    /// Only the tags are stored: the decoders are stateless empty structs
    /// the dispatcher reconstructs at the call site, so keeping the
    /// instances would buy nothing and cost an existential per slot.
    init(decoders: [any FamilyDecoder]) {
        var slotTags = [FamilyTag](repeating: .unregistered, count: 16)
        for decoder in decoders {
            for op0 in decoder.op0Values {
                slotTags[Int(op0)] = decoder.tag
            }
        }
        tags = slotTags
    }

    /// The concrete family type registered at `op0`, or
    /// ``FamilyTag/unregistered`` when no family claims it (in which case
    /// the dispatcher emits an UNDEFINED draft). `op0` is masked to 4
    /// bits, matching the dispatcher's extraction.
    @inline(__always)
    func tag(forOp0 op0: UInt8) -> FamilyTag {
        tags[Int(op0 & 0xF)]
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
        // op0=0 hosts Apple AMX + architectural SME (+ UDF, handled by the
        // dispatcher before family lookup): Op0ZeroDecoder multiplexes them.
        // op0=2 is the SVE / SVE2 tier. Both were formerly reserved →
        // UNDEFINED; SME/SVE decode is gated on the respective Features.
        Op0ZeroDecoder(),
        SVEDecoder(),
    ])
}

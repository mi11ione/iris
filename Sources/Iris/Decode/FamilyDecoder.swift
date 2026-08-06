// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Per-encoding-family decoder registration surface.
protocol FamilyDecoder: Sendable {
    /// The `op0` values this family handles.
    var op0Values: Set<UInt8> { get }

    /// This family's dispatcher tag.
    var tag: FamilyTag { get }

    /// Decode one 4-byte word, preferred aliases resolved.
    func decode(
        encoding: UInt32,
        address: UInt64,
        features: Features,
        _ sink: inout OperandSink,
    ) -> DecodedDraft
}

/// Which concrete family decoder occupies a dispatcher slot.
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
struct FamilyDecoderSet: Sendable {
    /// Per-`op0` concrete family identity.
    let tags: [FamilyTag]

    /// Build the dispatcher table.
    init(decoders: [any FamilyDecoder]) {
        var slotTags = [FamilyTag](repeating: .unregistered, count: 16)
        for decoder in decoders {
            for op0 in decoder.op0Values {
                slotTags[Int(op0)] = decoder.tag
            }
        }
        tags = slotTags
    }

    /// The family registered at `op0`, masked to 4 bits, or
    /// ``FamilyTag/unregistered`` when none claims it.
    @inline(__always)
    func tag(forOp0 op0: UInt8) -> FamilyTag {
        tags[Int(op0 & 0xF)]
    }

    /// The default dispatcher table, composing every shipped family.
    static let standard: FamilyDecoderSet = .init(decoders: [
        DataProcessingImmediateDecoder(),
        BranchesExceptionSystemDecoder(),
        DataProcessingRegisterDecoder(),
        LoadsAndStoresDecoder(),
        SIMDAndFPDecoder(),
        Op0ZeroDecoder(),
        SVEDecoder(),
    ])
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SVE / SVE2 family decoder, registered for `op0=0b0010`.
struct SVEDecoder: FamilyDecoder, Sendable {
    static let sveOp0Values: Set<UInt8> = [0b0010]

    init() {}

    var tag: FamilyTag {
        .sve
    }

    var op0Values: Set<UInt8> {
        Self.sveOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if isSVEPredicateControlEncoding(encoding) {
            return SVEPredicateControlDecode.decode(encoding: encoding, address: address, &sink)
        }
        if isSVEIntegerEncoding(encoding) {
            return SVEIntegerDecode.decode(encoding: encoding, address: address, &sink)
        }
        if isSVEFloatingPointEncoding(encoding) {
            return SVEFloatingPointDecode.decode(encoding: encoding, address: address, &sink)
        }
        if isSVEPermuteMemoryCryptoEncoding(encoding) {
            return SVEPermuteMemoryDecode.decode(encoding: encoding, address: address, &sink)
        }
        return SME2PredicateDecode.decode(encoding: encoding, address: address, &sink)
    }
}

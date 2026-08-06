// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The composite family decoder registered for `op0=0b0000`.
struct Op0ZeroDecoder: FamilyDecoder, Sendable {
    static let op0ZeroValues: Set<UInt8> = [0b0000]
    static let amx = AMXDecoder()
    static let sme = SMEDecoder()

    init() {}

    var tag: FamilyTag {
        .op0Zero
    }

    var op0Values: Set<UInt8> {
        Self.op0ZeroValues
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if isAMXEncoding(encoding) {
            return Self.amx.decode(encoding: encoding, address: address, features: features, &sink)
        }
        if isSMEEncoding(encoding) {
            return Self.sme.decode(encoding: encoding, address: address, features: features, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SME / SME2 decoder for the SME region of `op0=0b0000`.
struct SMEDecoder: Sendable {
    init() {}

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if isSMECoreEncoding(encoding) {
            return SMECoreDecode.decode(encoding: encoding, address: address, &sink)
        }
        return SME2Decode.decode(encoding: encoding, address: address, &sink)
    }
}

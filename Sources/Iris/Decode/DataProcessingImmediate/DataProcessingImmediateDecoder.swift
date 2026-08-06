// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The Data Processing.
struct DataProcessingImmediateDecoder: FamilyDecoder {
    /// Precomputed op0 set returned by ``op0Values``.
    private static let dpiOp0Values: Set<UInt8> = [0x8, 0x9]

    init() {}

    var tag: FamilyTag {
        .dataProcessingImmediate
    }

    var op0Values: Set<UInt8> {
        Self.dpiOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let op1 = UInt8((encoding >> 23) & 0x7)
        if op1 <= 0b001 {
            return PCRelDecode.decode(encoding: encoding, address: address, &sink)
        }
        if op1 == 0b010 {
            return AddSubImmDecode.decode(encoding: encoding, address: address, &sink)
        }
        if op1 == 0b011 {
            if (encoding >> 22) & 1 == 1 {
                return MinMaxImmDecode.decode(encoding: encoding, address: address, &sink)
            }
            if let mteDraft = MemoryTaggingDecode.decodeDPI(
                encoding: encoding, address: address, &sink,
            ) {
                return mteDraft
            }
            return .undefined(at: address, encoding: encoding)
        }
        if op1 == 0b100 {
            return LogicalImmDecode.decode(encoding: encoding, address: address, &sink)
        }
        if op1 == 0b101 {
            return MoveWideDecode.decode(encoding: encoding, address: address, &sink)
        }
        if op1 == 0b110 {
            return BitfieldDecode.decode(encoding: encoding, address: address, &sink)
        }
        if let pauthLR = PointerAuthenticationDecode.decodeImmediate(
            encoding: encoding, address: address, &sink,
        ) {
            return pauthLR
        }
        return ExtractDecode.decode(encoding: encoding, address: address, &sink)
    }
}

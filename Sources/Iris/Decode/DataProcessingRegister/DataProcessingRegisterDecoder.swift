// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The Data Processing.
struct DataProcessingRegisterDecoder: FamilyDecoder {
    static let dprOp0Values: Set<UInt8> = [0x5, 0xD]

    init() {}

    var tag: FamilyTag {
        .dataProcessingRegister
    }

    var op0Values: Set<UInt8> {
        Self.dprOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let op0 = UInt8((encoding >> 25) & 0xF)
        if (encoding & 0x9FE0_0000) == 0x9AC0_0000 {
            if let pacOneSource = PointerAuthenticationDecode.decodeOneSource(
                encoding: encoding, address: address, &sink,
            ) {
                return pacOneSource
            }
            if let pacga = PointerAuthenticationDecode.decodeTwoSource(
                encoding: encoding, address: address, &sink,
            ) {
                return pacga
            }
            if let mteDPR = MemoryTaggingDecode.decodeDPR(
                encoding: encoding, address: address, &sink,
            ) {
                return mteDPR
            }
        }
        let bit24 = (encoding >> 24) & 1
        if op0 == 0x5 {
            if bit24 == 0 {
                return LogicalShiftedDecode.decode(encoding: encoding, address: address, &sink)
            }
            return AddSubRegisterDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bit24 == 1 {
            return MulAccumDecode.decode(encoding: encoding, address: address, &sink)
        }
        let bits23_21 = UInt8((encoding >> 21) & 0x7)
        switch bits23_21 {
        case 0b000:
            return AddSubCarryDecode.decode(encoding: encoding, address: address, &sink)
        case 0b010:
            return CondCompareDecode.decode(encoding: encoding, address: address, &sink)
        case 0b100:
            return CondSelectDecode.decode(encoding: encoding, address: address, &sink)
        case 0b110:
            return DataProc2or1SourceDecode.decode(encoding: encoding, address: address, &sink)
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}

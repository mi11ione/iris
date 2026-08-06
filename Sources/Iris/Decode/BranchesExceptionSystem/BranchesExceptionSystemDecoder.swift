// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The Branches, Exception, System family decoder.
struct BranchesExceptionSystemDecoder: FamilyDecoder {
    private static let besOp0Values: Set<UInt8> = [0xA, 0xB]

    init() {}

    var tag: FamilyTag {
        .branchesExceptionSystem
    }

    var op0Values: Set<UInt8> {
        Self.besOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let bits31_24 = UInt8((encoding >> 24) & 0xFF)
        switch bits31_24 {
        case 0x14, 0x15, 0x16, 0x17:
            return BranchImmDecode.decodeB(encoding: encoding, address: address, &sink)
        case 0x94, 0x95, 0x96, 0x97:
            return BranchImmDecode.decodeBL(encoding: encoding, address: address, &sink)
        case 0x54:
            return CondBranchDecode.decode(encoding: encoding, address: address, &sink)
        case 0x55:
            return ReturnPACImmDecode.decode(encoding: encoding, address: address, &sink)
        case 0x34, 0xB4:
            return CompareBranchDecode.decode(encoding: encoding, address: address, &sink)
        case 0x35, 0xB5:
            return CompareBranchDecode.decode(encoding: encoding, address: address, &sink)
        case 0x36, 0xB6:
            return TestBranchDecode.decode(encoding: encoding, address: address, &sink)
        case 0x37, 0xB7:
            return TestBranchDecode.decode(encoding: encoding, address: address, &sink)
        case 0x74, 0xF4, 0x75, 0xF5:
            return CompareBranchRegDecode.decode(encoding: encoding, address: address, &sink)
        case 0xD4:
            return ExceptionDecode.decode(encoding: encoding, address: address, &sink)
        case 0xD5:
            return SystemDecode.decode(encoding: encoding, address: address, &sink)
        case 0xD6, 0xD7:
            return BranchRegDecode.decode(encoding: encoding, address: address, &sink)
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}

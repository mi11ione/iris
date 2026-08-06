// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The top-level encoding-family dispatcher.
enum MachineCodeDecoder {
    /// Dispatch one 4-byte word.
    @inline(__always)
    static func dispatch(
        encoding: UInt32,
        address: UInt64,
        families: FamilyDecoderSet,
        features: Features,
        _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let op0 = UInt8((encoding >> 25) & 0xF)
        if op0 == 0, encoding & 0xFFFF_0000 == 0 {
            return .udf(at: address, encoding: encoding, &sink)
        }
        switch families.tag(forOp0: op0) {
        case .unregistered:
            return .undefined(at: address, encoding: encoding)
        case .dataProcessingImmediate:
            return DataProcessingImmediateDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .branchesExceptionSystem:
            return BranchesExceptionSystemDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .loadsAndStores:
            return LoadsAndStoresDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .dataProcessingRegister:
            return DataProcessingRegisterDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .simdAndFP:
            return SIMDAndFPDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .op0Zero:
            return Op0ZeroDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        case .sve:
            return SVEDecoder()
                .decode(encoding: encoding, address: address, features: features, &sink)
        }
    }
}

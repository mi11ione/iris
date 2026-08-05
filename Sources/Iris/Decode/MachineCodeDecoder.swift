// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MachineCodeDecoder. The dispatcher entry point: extract op0, look up
// the family decoder, invoke it. Single straight-line path; no
// allocation in the common case. Wrapped by the public tier-0
// `decode(_:at:features:)` and the `InstructionStream` decoding
// initializer.

/// The top-level encoding-family dispatcher.
///
/// `MachineCodeDecoder.dispatch(encoding:address:families:features:)` is
/// the single per-word entry point: extract `op0` from bits [28:25],
/// look up the family decoder, invoke `decode`. The one dispatcher-owned
/// exception to family dispatch is `UDF` — the single allocated encoding
/// of the `op0=0` reserved tier — recognized directly before family
/// lookup. The dispatcher itself is a pure function — all state is in
/// `families` and `features`.
enum MachineCodeDecoder {
    /// Dispatch a single 4-byte word through the registered family
    /// decoders. Returns the resulting draft; callers commit it into
    /// record + operand storage.
    @inline(__always)
    static func dispatch(
        encoding: UInt32,
        address: UInt64,
        families: FamilyDecoderSet,
        features: Features,
        _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let op0 = UInt8((encoding >> 25) & 0xF)
        // UDF (Permanently Undefined) is the one allocated encoding in the
        // op0=0 reserved tier: bits[31:16] == 0, imm16 = bits[15:0]. The
        // dispatcher owns it before family dispatch — no family claims it,
        // and AMX (also op0=0) never collides because every AMX encoding
        // sets bits in 0x00201000, so its bits[31:16] are never zero.
        if op0 == 0, encoding & 0xFFFF_0000 == 0 {
            return .udf(at: address, encoding: encoding, &sink)
        }
        // Dispatch to the family CONCRETELY where the slot holds one of
        // the shipped types. Going through the `[(any FamilyDecoder)?]`
        // table instead is a witness-table call in front of the whole
        // decode tree, once per instruction, that no optimizer can see
        // through. Every family is a stateless empty struct, so calling a
        // freshly-constructed one is indistinguishable from calling a
        // stored instance. The switch has no `default`: a new family
        // cannot be registered without gaining a branch here.
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

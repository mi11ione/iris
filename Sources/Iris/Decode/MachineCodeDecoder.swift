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
    ) -> DecodedDraft {
        let op0 = UInt8((encoding >> 25) & 0xF)
        // UDF (Permanently Undefined) is the one allocated encoding in the
        // op0=0 reserved tier: bits[31:16] == 0, imm16 = bits[15:0]. The
        // dispatcher owns it before family dispatch — no family claims it,
        // and AMX (also op0=0) never collides because every AMX encoding
        // sets bits in 0x00201000, so its bits[31:16] are never zero.
        if op0 == 0, encoding & 0xFFFF_0000 == 0 {
            return .udf(at: address, encoding: encoding)
        }
        guard let family = families.familyForOp0(op0) else {
            return .undefined(at: address, encoding: encoding)
        }
        return family.decode(encoding: encoding, address: address, features: features)
    }
}

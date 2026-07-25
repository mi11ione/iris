// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// composite decoder for op0 = 0b0000 — the fix for the one-decoder-per-
// op0 limit now that op0=0 hosts both Apple AMX and architectural SME
// (alongside UDF). UDF is handled by the dispatcher before family lookup
// (bits[31:16]==0, disjoint from SME's bit31=1), so this composite sees only
// non-UDF op0=0 words: it routes AMX magic encodings to the AMXDecoder,
// the SME region (bit31=1) to the SMEDecoder, and everything else (genuine
// holes) to UNDEFINED. Mirrors the established delegation pattern
// (SIMDAndFPDecoder delegates crypto to CryptoExtensionDecode).

/// The composite family decoder registered for `op0=0b0000`.
///
/// Delegates by encoding: ``isAMXEncoding(_:)`` → the ``AMXDecoder``;
/// ``isSMEEncoding(_:)`` → the ``SMEDecoder`` (SME region); otherwise a
/// well-formed UNDEFINED record for the genuine reserved holes. Its
/// ``identifier`` is ``FamilyIdentifier/sme`` — `op0=0b0000` is the
/// architectural SME tier; AMX is an implementation-defined squat verified
/// by-encoding (``MachineCodeDecoder/familyIdentifier(forEncoding:in:context:)``).
struct Op0ZeroDecoder: FamilyDecoder, Sendable {
    static let op0ZeroValues: Set<UInt8> = [0b0000]
    static let amx = AMXDecoder()
    static let sme = SMEDecoder()

    init() {}

    var op0Values: Set<UInt8> {
        Self.op0ZeroValues
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features: Features,
    ) -> DecodedDraft {
        if isAMXEncoding(encoding) {
            return Self.amx.decode(encoding: encoding, address: address, features: features)
        }
        if isSMEEncoding(encoding) {
            // The SME region (bit31=1) decodes only with the SME feature
            // enabled; absent it, it reads as honest UNDEFINED.
            guard features.contains(.sme) else {
                return .undefined(at: address, encoding: encoding)
            }
            return Self.sme.decode(encoding: encoding, address: address, features: features)
        }
        // Genuine op0=0 hole (non-UDF, non-AMX, non-SME) — UNDEFINED. UDF is
        // handled by the dispatcher before family lookup.
        return .undefined(at: address, encoding: encoding)
    }
}

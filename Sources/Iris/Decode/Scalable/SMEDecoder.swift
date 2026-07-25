// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SME sub-decoder — decodes the SME region of op0 = 0b0000 (bit31=1).
// Invoked by Op0ZeroDecoder after isSMEEncoding holds, so bit31=1 and the
// four primary groups (bits[31:29] in {100,101,110,111}) are exhaustive.
// Partitions the region between the SME-core region (outer products, ZA load/
// store/move/zero) and the SME2 region (ZT0, LUTI): `isSMECoreEncoding`
// routes to `SMECoreDecode`, its exact complement to `SME2Decode`. Every word
// decodes in one or the other, or yields a well-formed UNDEFINED (category
// .sme) for a genuine architectural hole.

/// The SME / SME2 decoder for the SME region of `op0=0b0000`.
///
/// Not a registered ``FamilyDecoder`` — the composite ``Op0ZeroDecoder``
/// (which also hosts AMX) holds the `op0=0b0000` slot in
/// ``FamilyDecoderSet/standard`` and delegates here when ``isSMEEncoding(_:)``
/// holds. Core encodings decode in SME-core, their complement (SME2
/// multi-vector / ZT0 / LUTI) in SME2.
struct SMEDecoder: Sendable {
    init() {}

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // the SME-core decoder owns its region (outer products, ZA load/store/move/
        // zero); the gate is `isSMECoreEncoding`, the exact complement of the
        // SME2 multi-vector / ZT0 / LUTI region the SME2 decoder claims. The two partition
        // the whole SME region: every word decodes in one or the other (or
        // yields a well-formed UNDEFINED for a genuine hole, `category = .sme`).
        if isSMECoreEncoding(encoding) {
            return SMECoreDecode.decode(encoding: encoding, address: address)
        }
        return SME2Decode.decode(encoding: encoding, address: address)
    }
}

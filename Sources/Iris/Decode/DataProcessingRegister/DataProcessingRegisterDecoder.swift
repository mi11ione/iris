// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level FamilyDecoder for the Data Processing —
// Register tier (op0 ∈ {0x5, 0xD}). Sub-dispatches by
// (bit 28, bit 24, bits 23:21). Alias resolution is inlined per
// sub-class following the DPI + BES pattern.

/// The Data Processing — Register family decoder. Conforms to
/// ``FamilyDecoder`` and is registered in ``FamilyDecoderSet/standard`` so
/// the dispatcher routes op0 ∈ {0x5, 0xD} encodings here.
struct DataProcessingRegisterDecoder: FamilyDecoder {
    static let dprOp0Values: Set<UInt8> = [0x5, 0xD]

    init() {}

    var op0Values: Set<UInt8> {
        Self.dprOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // The dispatcher's op0-slab routing guarantees op0 ∈ {0x5, 0xD};
        // the bit is still needed for the sub-dispatch below.
        let op0 = UInt8((encoding >> 25) & 0xF)
        // Crypto/Apple-extensions delegation: PAC standalone, PACGA,
        // MTE-DPR. Each entry
        // point self-validates its row prefix and returns nil for
        // non-matching encodings. Placed before the DPR sub-dispatch so
        // SUBPS (S=1, outside DPR's S=0 sub-tree) reaches MTE-DPR.
        if let pacOneSource = PointerAuthenticationDecode.decodeOneSource(
            encoding: encoding, address: address,
        ) {
            return pacOneSource
        }
        if let pacga = PointerAuthenticationDecode.decodeTwoSource(
            encoding: encoding, address: address,
        ) {
            return pacga
        }
        if let mteDPR = MemoryTaggingDecode.decodeDPR(
            encoding: encoding, address: address,
        ) {
            return mteDPR
        }
        let bit24 = (encoding >> 24) & 1
        if op0 == 0x5 {
            if bit24 == 0 {
                return LogicalShiftedDecode.decode(encoding: encoding, address: address)
            }
            return AddSubRegisterDecode.decode(encoding: encoding, address: address)
        }
        // op0 == 0xD.
        if bit24 == 1 {
            return MulAccumDecode.decode(encoding: encoding, address: address)
        }
        // op0=0xD bit 24=0 — sub-dispatch by bits 23:21.
        let bits23_21 = UInt8((encoding >> 21) & 0x7)
        switch bits23_21 {
        case 0b000:
            return AddSubCarryDecode.decode(encoding: encoding, address: address)
        case 0b010:
            return CondCompareDecode.decode(encoding: encoding, address: address)
        case 0b100:
            return CondSelectDecode.decode(encoding: encoding, address: address)
        case 0b110:
            return DataProc2or1SourceDecode.decode(encoding: encoding, address: address)
        default:
            // bits 23:21 ∈ {001, 011, 101, 111} — reserved in this sub-tree.
            // (FlagM and CPA share bits 23:21=000, handled above; CSSC is in
            // the 110 path.)
            return .undefined(at: address, encoding: encoding)
        }
    }
}

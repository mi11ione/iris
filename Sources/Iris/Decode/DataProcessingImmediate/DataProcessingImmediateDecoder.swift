// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level FamilyDecoder for the Data Processing —
// Immediate tier (op0 ∈ {0x8, 0x9}). Dispatches by op1
// (bits 25:23) to per-class decoders. The op1=0b011 sub-dispatch
// (ADDG/SUBG MTE) delegates to the MTE decoder.
//
// Alias resolution is inlined per-class — each decoded class picks its
// preferred alias before the draft leaves the family, so UNDEFINED
// drafts are never rewritten.

/// The Data Processing — Immediate family decoder. Conforms to
/// `FamilyDecoder` and is registered in `FamilyDecoderSet.standard` so
/// the dispatcher routes op0 ∈ {0x8, 0x9} encodings here.
struct DataProcessingImmediateDecoder: FamilyDecoder {
    /// Precomputed op0 set returned by ``op0Values`` — built once at module
    /// load so `FamilyDecoderSet.init` doesn't reallocate this Set on
    /// every invocation.
    private static let dpiOp0Values: Set<UInt8> = [0x8, 0x9]

    init() {}

    var op0Values: Set<UInt8> {
        Self.dpiOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // The dispatcher's op0-slab routing guarantees op0 ∈ {0x8, 0x9}.
        // op1 = bits 25:23. Op0's LSB is also op1's MSB, so the (op0,
        // op1) pair is structurally constrained: op0=0x8 ⇒ op1 ∈ {000,
        // 001, 010, 011}; op0=0x9 ⇒ op1 ∈ {100, 101, 110, 111}.
        let op1 = UInt8((encoding >> 23) & 0x7)
        if op1 <= 0b001 {
            return PCRelDecode.decode(encoding: encoding, address: address)
        }
        if op1 == 0b010 {
            return AddSubImmDecode.decode(encoding: encoding, address: address)
        }
        if op1 == 0b011 {
            // ADDG / SUBG (MTE) — the MTE decoder owns this row.
            if let mteDraft = MemoryTaggingDecode.decodeDPI(
                encoding: encoding, address: address,
            ) {
                return mteDraft
            }
            return .undefined(at: address, encoding: encoding)
        }
        if op1 == 0b100 {
            return LogicalImmDecode.decode(encoding: encoding, address: address)
        }
        if op1 == 0b101 {
            return MoveWideDecode.decode(encoding: encoding, address: address)
        }
        if op1 == 0b110 {
            return BitfieldDecode.decode(encoding: encoding, address: address)
        }
        // `op1` is masked to three bits, so after handling 000...110 this
        // final path is op1 == 111.
        return ExtractDecode.decode(encoding: encoding, address: address)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level FamilyDecoder for Branches, Exception, System
// (op0 ∈ {0xA, 0xB}). Sub-dispatches on bits 31:24 to one
// of seven per-class decoders. Alias resolution is inlined per-class
// following DPI's pattern.

/// The Branches, Exception, System family decoder. Conforms to
/// `FamilyDecoder` and is registered in `FamilyDecoderSet.standard` so
/// the dispatcher routes op0 ∈ {0xA, 0xB} encodings here.
struct BranchesExceptionSystemDecoder: FamilyDecoder {
    private static let besOp0Values: Set<UInt8> = [0xA, 0xB]

    init() {}

    var op0Values: Set<UInt8> {
        Self.besOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // Sub-dispatch on bits 31:24 per the ARM ARM class table.
        let bits31_24 = UInt8((encoding >> 24) & 0xFF)
        switch bits31_24 {
        // B (unconditional branch immediate) — 4 encodings 0x14..0x17.
        case 0x14, 0x15, 0x16, 0x17:
            return BranchImmDecode.decodeB(encoding: encoding, address: address)
        // BL — 4 encodings 0x94..0x97.
        case 0x94, 0x95, 0x96, 0x97:
            return BranchImmDecode.decodeBL(encoding: encoding, address: address)
        // Conditional branch — single bits 31:24 = 0x54.
        case 0x54:
            return CondBranchDecode.decode(encoding: encoding, address: address)
        // CBZ — 32-bit (sf=0) at 0x34; 64-bit (sf=1) at 0xB4.
        case 0x34, 0xB4:
            return CompareBranchDecode.decode(encoding: encoding, address: address)
        // CBNZ — 32-bit at 0x35; 64-bit at 0xB5.
        case 0x35, 0xB5:
            return CompareBranchDecode.decode(encoding: encoding, address: address)
        // TBZ — bit-pos<32 at 0x36; bit-pos>=32 at 0xB6.
        case 0x36, 0xB6:
            return TestBranchDecode.decode(encoding: encoding, address: address)
        // TBNZ — bit-pos<32 at 0x37; bit-pos>=32 at 0xB7.
        case 0x37, 0xB7:
            return TestBranchDecode.decode(encoding: encoding, address: address)
        // FEAT_CMPBR compare-and-branch — register/byte/halfword at 0x74
        // (sf=0) / 0xF4 (sf=1); immediate at 0x75 / 0xF5.
        case 0x74, 0xF4, 0x75, 0xF5:
            return CompareBranchRegDecode.decode(encoding: encoding, address: address)
        // Exception generation.
        case 0xD4:
            return ExceptionDecode.decode(encoding: encoding, address: address)
        // System (HINT / barrier / MSR-imm / WFXT / SYS / SYSL / MSR-reg / MRS).
        case 0xD5:
            return SystemDecode.decode(encoding: encoding, address: address)
        // Branch register (regular + auth).
        case 0xD6, 0xD7:
            return BranchRegDecode.decode(encoding: encoding, address: address)
        default:
            // op0 ∈ {0xA, 0xB} guarantees bits 28:25 = 101x, but the full
            // bits 31:24 covers 8 bits; not every combination corresponds
            // to an encoded family. Unmatched → .undefined (per Vision
            // invariant 4: silent skip, never silent guess).
            return .undefined(at: address, encoding: encoding)
        }
    }
}

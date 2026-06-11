// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level FamilyDecoder for the SIMD & Floating-Point tier
// (top-level op0 ∈ {0x7, 0xF}). Sub-dispatches per the SIMD/FP encoding
// tree in ARM ARM § C4.1.96: scalar copy / scalar three-same /
// scalar two-reg-misc / scalar pairwise / scalar three-different / scalar
// shift-by-imm / scalar x-indexed / vector copy / permute / extract /
// table lookup / vector three-same / vector two-reg-misc / vector
// three-reg-extension / vector across-lanes / vector three-different /
// vector modified-imm / vector shift-by-imm / vector x-indexed / FP fixed-
// point / FP integer / FP 1-source / FP compare / FP imm / FP cond-compare
// / FP 2-source / FP cond-select / FP 3-source.
//
// V=1 SIMD/FP load/store encodings (NEON structured LD/ST and scalar SIMD
// LDR/STR/LDP/STP/LDUR/STUR/literal) live at op0 ∈ {0x4, 0x6, 0xC, 0xE}
// with bit[26]=1. They reach this family via delegation from
// `LoadsAndStoresDecoder.decode(...)` calling
// ``SIMDAndFPDecoder/decodeVectorLoadStore(encoding:address:)``.
//
// Crypto encodings (AES/SHA/SM3/SM4/EOR3/XAR/BCAX/RAX1) fall in this slab
// at specific bit[31:24] prefixes and are delegated to the crypto decoder
// before SIMD/FP dispatch.

/// The SIMD & Floating-Point family decoder. Conforms to ``FamilyDecoder``
/// and is registered in ``FamilyDecoderSet/standard`` so the dispatcher
/// routes op0 ∈ {0x7, 0xF} encodings here.
struct SIMDAndFPDecoder: FamilyDecoder {
    static let simdfpOp0Values: Set<UInt8> = [0x7, 0xF]

    init() {}

    var op0Values: Set<UInt8> {
        Self.simdfpOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        // The dispatcher's op0-slab routing guarantees op0 ∈ {0x7, 0xF};
        // V=1 loads/stores at op0 ∈ {0x4, 0x6, 0xC, 0xE} arrive through
        // `decodeVectorLoadStore` via the L/S delegation instead.
        // Crypto delegation: crypto encodings (AES / SHA / SM3 / SM4) live
        // in this slab at specific bit[31:24] prefixes. CryptoExtensionDecode
        // returns nil for non-crypto encodings, letting the SIMD/FP
        // dispatch below run unchanged.
        if let cryptoDraft = CryptoExtensionDecode.decode(
            encoding: encoding, address: address,
        ) {
            return cryptoDraft
        }
        let bits31_24 = UInt8((encoding >> 24) & 0xFF)

        // FP scalar classes occupy bit[30] = 0, bits[28:25] = 1111 (bit[24]
        // selects the 0x1E sub-tree vs FP DP 3-source). bit[29] = S is a
        // fixed 0; S = 1 is reserved → UNDEFINED. The inner decoders do not
        // re-check S, so the routing must (the AdvSIMD scalar tier 0x5E/0x7E
        // has bit[30] = 1 and is handled by the switch below). bit[31]
        // (M / sf) varies and is left to the sub-decoders.
        if (encoding >> 30) & 1 == 0, (encoding >> 25) & 0xF == 0b1111 {
            if (encoding >> 29) & 1 == 1 {
                return .undefined(at: address, encoding: encoding)
            }
            if (encoding >> 24) & 1 == 0 {
                return dispatchFPScalar0x1E(encoding: encoding, address: address)
            }
            return FPDataProcessing3SourceDecode.decode(encoding: encoding, address: address)
        }
        // AdvSIMD encoding sub-tree. bits[31:24] high nibble selects:
        //   0x0E / 0x2E / 0x4E / 0x6E — vector tier with bit[24]=0
        //     (three-same / two-reg-misc / across-lanes / three-different
        //     / vector copy / permute / extract / table-lookup).
        //   0x0F / 0x2F / 0x4F / 0x6F — vector tier with bit[24]=1
        //     (modified-immediate / shift-by-immediate / vector x-indexed-
        //     element / three-reg-extension).
        //   0x5E / 0x7E / 0x5F / 0x7F — AdvSIMD scalar tier (three-same,
        //     two-reg-misc, three-different, pairwise, shift-by-imm,
        //     x-indexed-element).
        // With op0 ∈ {0x7, 0xF} validated upstream, bits31_24 & 0b1001_1111
        // is always one of the four listed values; the final case is
        // folded into `default` to keep the switch exhaustive without an
        // unreachable arm.
        // bit[31] is a fixed 0 across both AdvSIMD tiers (the FP-scalar
        // sub-tree above owns its own bit[31]); bit[31] = 1 reaching here is
        // reserved, so reject it before the tier switch (otherwise the
        // bit[31]-preserving mask folds it into the scalar-x-indexed default).
        if bits31_24 & 0b1000_0000 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        switch bits31_24 & 0b1001_1111 {
        case 0b0000_1110: // 0x0E / 0x2E / 0x4E / 0x6E — vector arithmetic
            return dispatchAdvSIMDVector0xX_E(encoding: encoding, address: address)
        case 0b0000_1111: // 0x0F / 0x2F / 0x4F / 0x6F — vector immediate/shift/indexed
            return dispatchAdvSIMDVector0xX_F(encoding: encoding, address: address)
        case 0b0001_1110: // 0x5E / 0x7E — scalar arithmetic
            return dispatchAdvSIMDScalar0xX_E(encoding: encoding, address: address)
        default: // 0b0001_1111 — 0x5F / 0x7F — scalar shift/indexed
            return dispatchAdvSIMDScalar0xX_F(encoding: encoding, address: address)
        }
    }

    /// AdvSIMD vector dispatch within bits[31:24] high nibble = 0xX_E
    /// (bit[24]=0). Sub-discriminates by bit[21] (1 = three-arg classes;
    /// 0 = copy / permute / extract / TBL).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDVector0xX_E(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 1 {
            return dispatchVectorThreeArg(encoding: encoding, address: address)
        }
        return dispatchVectorNonThreeArg(encoding: encoding, address: address)
    }

    /// Three-arg vector classes (three-same / three-different / two-reg-misc
    /// / across-lanes). Discriminate by bit[10] + bits[20:17].
    @inline(__always)
    @_optimize(speed)
    private func dispatchVectorThreeArg(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit10 == 1 {
            // Three-same (vector).
            return AdvSIMDThreeSameDecode.decode(encoding: encoding, address: address)
        }
        // bit[10] = 0 — three-different / two-reg-misc / across-lanes.
        if bit11 == 0 {
            // Three-different has bits[11:10] = 00.
            return AdvSIMDThreeDifferentDecode.decode(encoding: encoding, address: address)
        }
        // bits[11:10] = 10 — two-reg-misc or across-lanes; discriminate by
        // bits[20:17] (the next-after-bit[21] discriminator within
        // bits[21:17]). Two-reg-misc has bits[21:17] = 10000 ⇒ bits[20:17]
        // = 0000; across-lanes has bits[21:17] = 11000 ⇒ bits[20:17] = 1000.
        let bits20_17 = UInt8((encoding >> 17) & 0xF)
        if bits20_17 == 0b0000 {
            return AdvSIMDTwoRegMiscDecode.decode(encoding: encoding, address: address)
        }
        if bits20_17 == 0b1000 {
            return AdvSIMDAcrossLanesDecode.decode(encoding: encoding, address: address)
        }
        // FP16 two-reg-misc has bits[21:17] = 11100 ⇒ bits[20:17] = 1100.
        if bits20_17 == 0b1100 {
            return AdvSIMDTwoRegMiscDecode.decodeFP16TwoRegMisc(encoding: encoding, address: address)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// Non-three-arg vector classes (copy / permute / extract / TBL /
    /// three-reg-extension). Discriminate by bit[15] + bit[10] first, then
    /// — within the bit[15]=0, bit[10]=0 branch — by bit[29] (EXT has
    /// bits[29:28]=10; TBL/permute share bits[29:28]=00). bit[11] then
    /// separates permute (bit[11]=1) from TBL/TBX (bit[11]=0). EXT's
    /// bit[11] is part of imm4 and varies, so it must be discriminated by
    /// bit[29] BEFORE inspecting bit[11].
    @inline(__always)
    @_optimize(speed)
    private func dispatchVectorNonThreeArg(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit15 = (encoding >> 15) & 1
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit15 == 1, bit10 == 1 {
            // Three-reg-extension (DOT/MMLA family) — bit[21]=0,
            // bit[15]=1, bit[10]=1.
            return AdvSIMDThreeRegExtensionDecode.decode(
                encoding: encoding, address: address,
            )
        }
        if bit15 == 0, bit10 == 1 {
            // bit[21]=0, bit[15]=0, bit[10]=1 splits by bits[23:22]:
            //   00 → copy class; 01/11 (bit22=1) → three-same FP16
            //   (half-precision arithmetic); 10 → reserved.
            let bit22 = (encoding >> 22) & 1
            if bit22 == 1 {
                return AdvSIMDThreeSameFP16Decode.decode(encoding: encoding, address: address)
            }
            if (encoding >> 23) & 1 == 0 {
                return AdvSIMDCopyDecode.decode(encoding: encoding, address: address)
            }
            return .undefined(at: address, encoding: encoding)
        }
        if bit15 == 0, bit10 == 0 {
            let bit29 = (encoding >> 29) & 1
            if bit29 == 1 {
                // EXT (bits[29:28] = 10). bit[11] is imm4[0] — variable.
                return AdvSIMDExtractDecode.decode(encoding: encoding, address: address)
            }
            // bits[29:28] = 00 (TBL/TBX, LUTI, or permute).
            if bit11 == 0 {
                // size (bits[23:22]) = 00 is TBL/TBX; non-zero is FEAT_LUT.
                if (encoding >> 22) & 0x3 == 0 {
                    return AdvSIMDTableLookupDecode.decode(encoding: encoding, address: address)
                }
                return AdvSIMDLUTDecode.decode(encoding: encoding, address: address)
            }
            // Permute (bits[11:10] = 10).
            return AdvSIMDPermuteDecode.decode(encoding: encoding, address: address)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// AdvSIMD vector dispatch within bits[31:24] high nibble = 0xX_F
    /// (bit[24]=1). Sub-discriminates by bits[23:22] (which for these
    /// classes is structurally fixed or part of immh/size).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDVector0xX_F(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        // bit[10] is the primary discriminator: x-indexed-element has
        // bit[10]=0; modified-immediate and shift-by-immediate both have
        // bit[10]=1. (A previous ordering keyed on bits[23:19]==0 first,
        // which wrongly stole bit[10]=0 x-indexed encodings — e.g. FDOT at
        // size=00 — into the modified-immediate decoder.)
        let bit10 = (encoding >> 10) & 1
        if bit10 == 0 {
            return AdvSIMDVectorXIndexedElementDecode.decode(
                encoding: encoding, address: address,
            )
        }
        // bit[10]=1: modified-immediate has immh (bits[23:19]) == 00000;
        // shift-by-immediate has immh != 0 (size from immh's first-set-bit).
        let bits23_19 = (encoding >> 19) & 0x1F
        if bits23_19 == 0 {
            return AdvSIMDModifiedImmediateDecode.decode(encoding: encoding, address: address)
        }
        return AdvSIMDShiftByImmediateDecode.decode(
            encoding: encoding, address: address,
        )
    }

    /// AdvSIMD scalar tier dispatch — bits[31:24] high nibble = 0xX_E
    /// where bit[28] = 1 (i.e. 0x5E / 0x7E).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDScalar0xX_E(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 0 {
            let bit15 = (encoding >> 15) & 1
            let bit14 = (encoding >> 14) & 1
            let bit10 = (encoding >> 10) & 1
            let bit22 = (encoding >> 22) & 1
            // Scalar three-same FP16: bit22=1, bits[15:14]=00, bit10=1.
            if bit10 == 1, bit22 == 1, bit15 == 0, bit14 == 0 {
                return AdvSIMDScalarThreeSameFP16Decode.decode(encoding: encoding, address: address)
            }
            // Scalar three-same-extra (RDM sqrdmlah/sqrdmlsh): bit15=1, bit10=1.
            if bit10 == 1, bit15 == 1 {
                return AdvSIMDScalarThreeSameFP16Decode.decodeRDM(encoding: encoding, address: address)
            }
            // Scalar copy (DUP element): U=0, bits[23:21]=000, bit15=0, bit10=1.
            if (encoding >> 29) & 1 == 0, (encoding >> 21) & 0x7 == 0, bit15 == 0, bit10 == 1 {
                return AdvSIMDScalarCopyDecode.decode(encoding: encoding, address: address)
            }
            return .undefined(at: address, encoding: encoding)
        }
        // bit21 == 1 — scalar three-arg or pair-class.
        let bit10 = (encoding >> 10) & 1
        let bit11 = (encoding >> 11) & 1
        if bit10 == 1 {
            return AdvSIMDScalarThreeSameDecode.decode(
                encoding: encoding, address: address,
            )
        }
        if bit11 == 0 {
            return AdvSIMDScalarThreeDifferentDecode.decode(
                encoding: encoding, address: address,
            )
        }
        // bits[11:10] = 10 — scalar two-reg-misc or pairwise. Same
        // bits[20:17] discrimination as the vector tier: two-reg-misc
        // has 0000, pairwise has 1000.
        let bits20_17 = (encoding >> 17) & 0xF
        if bits20_17 == 0b0000 {
            return AdvSIMDScalarTwoRegMiscDecode.decode(
                encoding: encoding, address: address,
            )
        }
        if bits20_17 == 0b1000 {
            return AdvSIMDScalarPairwiseDecode.decode(
                encoding: encoding, address: address,
            )
        }
        // Scalar FP16 two-reg-misc has bits[21:17] = 11100 ⇒ bits[20:17] = 1100.
        if bits20_17 == 0b1100 {
            return AdvSIMDScalarTwoRegMiscDecode.decodeFP16(encoding: encoding, address: address)
        }
        return .undefined(at: address, encoding: encoding)
    }

    /// AdvSIMD scalar dispatch within bits[31:24] high nibble = 0xX_F
    /// (i.e. 0x5F / 0x7F). Shift-by-immediate or x-indexed-element. The
    /// discriminator is bit[10]: shift-by-immediate has bit[10] = 1 (and
    /// requires immh != 0000 inside the sub-decoder); x-indexed-element
    /// has bit[10] = 0. immh / size etc. can be arbitrary in x-indexed
    /// form (size at bits[23:22], L at bit[21], M at bit[20], Rm[3:0] at
    /// bits[19:16] — none of which are constrained to be non-zero).
    @inline(__always)
    @_optimize(speed)
    private func dispatchAdvSIMDScalar0xX_F(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit10 = (encoding >> 10) & 1
        if bit10 == 1 {
            return AdvSIMDScalarShiftByImmediateDecode.decode(
                encoding: encoding, address: address,
            )
        }
        return AdvSIMDScalarXIndexedElementDecode.decode(
            encoding: encoding, address: address,
        )
    }

    /// Dispatch within the bits[31:24] == 0b00011110 sub-tree (FP scalar
    /// 1/2-source / compare / cond-/imm / fixed-point and integer
    /// conversion). Sub-discriminate by bit[21] then bits[14:10] / [11:10].
    @inline(__always)
    @_optimize(speed)
    private func dispatchFPScalar0x1E(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        let bit21 = (encoding >> 21) & 1
        if bit21 == 0 {
            // FP fixed-point conversion sub-class (bit[21] = 0 within
            // bits[31:24] = 0x1E).
            return FPFixedPointConversionDecode.decode(
                encoding: encoding, address: address,
            )
        }
        // bit[21] = 1 — one of: FP DP 1-source / 2-source / compare /
        // cond-compare / cond-select / immediate / FP integer conversion.
        // FP integer conversion has bits[14:10] = 00000 (and bits[20:16]
        // contain the opcode); the other sub-classes have bits[14:10] in
        // varying patterns.
        let bits14_10 = UInt8((encoding >> 10) & 0x1F)
        // FP integer conversion has bits[15:10] = 000000 (the full six-bit
        // tail, not just [14:10]) and uses bit[31] = sf, so check it before
        // the bit[31]=0 guard below. bit15=1 here is reserved (UNDEFINED).
        if (encoding >> 10) & 0x3F == 0b000000 {
            return FPIntegerConversionDecode.decode(
                encoding: encoding, address: address,
            )
        }
        // Every remaining FP-DP scalar form (1-source / 2-source / compare /
        // cond-compare / cond-select / immediate) has bit[31] (M) fixed 0;
        // M = 1 is reserved.
        if (encoding >> 31) & 1 == 1 {
            return .undefined(at: address, encoding: encoding)
        }
        if bits14_10 == 0b10000 {
            return FPDataProcessing1SourceDecode.decode(
                encoding: encoding, address: address,
            )
        }
        let bits11_10 = UInt8(bits14_10 & 0x3)
        switch bits11_10 {
        case 0b00:
            // FP compare has bits[15:10] = 001000; FP immediate has
            // bits[12:10] = 100. Discriminate by bit[12].
            let bit12 = (encoding >> 12) & 1
            if bit12 == 1 {
                return FPImmediateDecode.decode(encoding: encoding, address: address)
            }
            // Otherwise: must match the FP-compare bits[15:10] == 001000.
            if (encoding >> 10) & 0x3F == 0b001000 {
                return FPCompareDecode.decode(encoding: encoding, address: address)
            }
            return .undefined(at: address, encoding: encoding)
        case 0b01:
            return FPConditionalCompareDecode.decode(
                encoding: encoding, address: address,
            )
        case 0b10:
            return FPDataProcessing2SourceDecode.decode(
                encoding: encoding, address: address,
            )
        default:
            // bits11_10 == 0b11 — only remaining 2-bit pair.
            return FPConditionalSelectDecode.decode(
                encoding: encoding, address: address,
            )
        }
    }

    /// V=1 SIMD/FP load/store delegation entry. Called by
    /// ``LoadsAndStoresDecoder/decode(encoding:address:features:)`` when
    /// it detects bit[26]=1 at op0 ∈ {0x4, 0x6, 0xC, 0xE}.
    /// Dispatches to the per-class ScalarSIMD* / AdvSIMDLoadStore*
    /// sub-decoders.
    ///
    /// The L/S top-level dispatch (`bits[29:24]`) is mirrored here for
    /// V=1: literal-loads use 011000, scalar SIMD pair forms use
    /// 101000-101011, scalar SIMD indexed/unscaled use 111000, scalar
    /// SIMD unsigned-offset uses 111001, AdvSIMD multi-structure uses
    /// 001100, AdvSIMD single-structure uses 001101. Other discriminator
    /// values at V=1 are architecturally reserved → UNDEFINED.
    @_optimize(speed)
    static func decodeVectorLoadStore(
        encoding: UInt32, address: UInt64,
    ) -> DecodedDraft {
        // Sub-class dispatch mirrors the L/S top-level dispatch from
        // `LoadsAndStoresDecoder` for V=1 encodings only. bits[29:24]
        // selects the L/S sub-encoding shell; further sub-discriminators
        // pick the variant. The caller (L/S decoder) has already verified
        // bit[26] = V = 1, so every case value below has bit[26] = 1
        // (bit 2 of the 6-bit field).
        let bits29_24 = UInt8((encoding >> 24) & 0x3F)
        switch bits29_24 {
        case 0b001100:
            // AdvSIMD multi-structure (no-offset / post-indexed).
            return AdvSIMDLoadStoreMultipleStructuresDecode.decode(
                encoding: encoding, address: address,
            )
        case 0b001101:
            // AdvSIMD single-structure (no-offset / post-indexed).
            return AdvSIMDLoadStoreSingleStructureDecode.decode(
                encoding: encoding, address: address,
            )
        case 0b011100:
            // Scalar SIMD LDR-literal (PC-relative). V=1 sets bit[26].
            return ScalarSIMDLoadLiteralDecode.decode(
                encoding: encoding, address: address,
            )
        case 0b011101:
            // Scalar SIMD LRCPC2 STLUR/LDAPUR (unscaled, acquire/release).
            return ScalarSIMDLRCPC2Decode.decode(encoding: encoding, address: address)
        case 0b101100, 0b101101:
            // Scalar SIMD pair (LDP/STP/LDNP/STNP) — V=1 with the four
            // bits[25:24] indexing variants (no-allocate / post / signed /
            // pre).
            return ScalarSIMDLoadStorePairDecode.decode(
                encoding: encoding, address: address,
            )
        case 0b111100:
            // Scalar SIMD indexed / unscaled / register-offset / pre-/post-.
            return ScalarSIMDLoadStoreIndexedDecode.decode(
                encoding: encoding, address: address,
            )
        default:
            // 0b111101 (scalar SIMD unsigned-offset) — V=1 means op0 ∈
            // {6, E}, so bits[29:24] ranges over exactly the eight values
            // enumerated in this switch.
            return ScalarSIMDLoadStoreUnsignedOffsetDecode.decode(
                encoding: encoding, address: address,
            )
        }
    }
}

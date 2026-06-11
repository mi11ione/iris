// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Top-level FamilyDecoder for Loads & Stores
// (op0 ∈ {0x4, 0x6, 0xC, 0xE}, the x1x0 slab). Sub-dispatches per the
// L/S encoding tree: load literal, exclusive register/pair,
// load-acquire/store-release, LRCPC LDAPR, LOR LDLAR/STLLR, CAS family,
// load/store pair (with all writeback variants + LDPSW + STGP + LDNP/STNP),
// unscaled imm (LDUR/STUR + PRFUM), unprivileged (LDTR/STTR), post/pre-
// indexed, register offset, unsigned offset, LSE atomics + ST* aliases,
// LRCPC2 (LDAPUR/STLUR), ARM64E LDRAA/LDRAB.
//
// V=1 SIMD/FP L/S encodings are delegated to
// `SIMDAndFPDecoder.decodeVectorLoadStore(...)`, which decodes them
// (AdvSIMD multi/single-structure, scalar literal / LRCPC2 / pair). The
// L/S exhaustive sweep validates those V=1 forms through that path.

/// The Loads & Stores family decoder. Conforms to ``FamilyDecoder`` and
/// is registered in ``FamilyDecoderSet/standard`` so the dispatcher
/// routes op0 ∈ {0x4, 0x6, 0xC, 0xE} encodings here.
struct LoadsAndStoresDecoder: FamilyDecoder {
    static let lsOp0Values: Set<UInt8> = [0x4, 0x6, 0xC, 0xE]

    init() {}

    var op0Values: Set<UInt8> {
        Self.lsOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features: Features,
    ) -> DecodedDraft {
        // FEAT_MOPS CPY/SET must be detected BEFORE the V check: CPY/SETG
        // carry bit26 (o0) = 1, which the V test would misroute to SIMD.
        // The discriminant fixes bits 28,27,24,10 set and 29,25,21 clear,
        // leaving o0 / bits[23:22] / register fields free.
        if (encoding & 0x3B20_0C00) == 0x1900_0400 {
            return MOPSDecode.decode(encoding: encoding, address: address)
        }

        // V=1 (SIMD/FP load/store) is delegated to
        // ``SIMDAndFPDecoder/decodeVectorLoadStore(encoding:address:)``.
        let V = (encoding >> 26) & 1
        if V == 1 {
            return SIMDAndFPDecoder.decodeVectorLoadStore(
                encoding: encoding, address: address,
            )
        }

        let bits29_24 = UInt8((encoding >> 24) & 0x3F)
        switch bits29_24 {
        case 0b011000:
            // L1 — Load register (literal): LDR/LDRSW/PRFM literal.
            return LoadLiteralDecode.decode(encoding: encoding, address: address)

        case 0b001000:
            // L2 / L3 / L4 / L4c / L5 — share the exclusive+ordered shell.
            let bit21 = (encoding >> 21) & 1
            if bit21 == 0 {
                // L2 exclusive register OR L4 LDAR/STLR OR L4c LDLAR/STLLR.
                return LoadStoreExclusiveAndOrderedDecode.decode(
                    encoding: encoding, address: address,
                )
            }
            // bit21 == 1: L3 exclusive pair OR L5 CAS / CASP family.
            //   CAS  (non-pair): bit[31]=size_hi (10/11) — sz field is 2-bit;
            //                    bit[23]=1; bits[14:10] = 11111 FIXED.
            //   CASP (pair):     bit[31]=0 FIXED, bit[30]=sz (0=32-bit pair,
            //                    1=64-bit pair); bit[23]=0; bits[14:10] = 11111.
            //   Pair (LDXP/STXP/LDAXP/STLXP): bit[31]=1, bit[30]=size
            //                    (10/11 are valid; 00/01 reserved);
            //                    bit[23]=0; bits[14:10] = Rt2 (5-bit reg).
            //
            // Discriminator:
            //   bit[23]==1                              → CAS family
            //   bit[23]==0, bit[31]==0                  → CASP family
            //   bit[23]==0, bit[31]==1                  → exclusive pair
            let bit23 = (encoding >> 23) & 1
            let bit31 = (encoding >> 31) & 1
            if bit23 == 1 {
                return CompareAndSwapDecode.decode(encoding: encoding, address: address)
            }
            if bit31 == 0 {
                return CompareAndSwapDecode.decodeCASP(encoding: encoding, address: address)
            }
            return LoadStoreExclusivePairDecode.decode(encoding: encoding, address: address)

        case 0b001001:
            // FEAT_LSUI unprivileged exclusive + compare-and-swap.
            return LSUILoadStoreDecode.decode(encoding: encoding, address: address)

        case 0b101000, 0b101001:
            // L6 — Load/store register pair (no-allocate / post / signed / pre).
            return LoadStorePairDecode.decode(encoding: encoding, address: address)

        case 0b111000:
            // L4b LDAPR, L7, L8, L9, L10, L11, L13, L15 share this shell.
            let bit21 = (encoding >> 21) & 1
            let bits11_10 = UInt8((encoding >> 10) & 0x3)
            if bit21 == 0 {
                switch bits11_10 {
                case 0b00:
                    return LoadStoreUnscaledDecode.decode(encoding: encoding, address: address)
                case 0b01:
                    return LoadStoreIndexedDecode.decode(
                        encoding: encoding, address: address, writebackKind: .postIndex,
                    )
                case 0b10:
                    return LoadStoreUnprivilegedDecode.decode(encoding: encoding, address: address)
                // bits[11:10] ∈ {00,01,10,11} all enumerated; 0b11
                // (pre-indexed) is `default`.
                default:
                    return LoadStoreIndexedDecode.decode(
                        encoding: encoding, address: address, writebackKind: .preIndex,
                    )
                }
            }
            // bit21 == 1: L4b LDAPR, L13 LSE atomic, L11 register offset, L15 LDRAA/LDRAB.
            switch bits11_10 {
            case 0b00:
                // FEAT_LS64 (size=11, bits[23:22]=00) shares the plain-ordering
                // cell with the LSE RMW/SWP ops; its op codes 1001/1010/1011/
                // 1101 sit above the LSE op range (0000..1000). At size 00/01
                // those op codes 1001/1010/1011 are FEAT_THE RCW non-pair
                // clr/swp/set instead. Detect both before the LDAPR / LSE split.
                let opHi = (encoding >> 12) & 0xF
                if opHi == 0b1001 || opHi == 0b1010 || opHi == 0b1011 || opHi == 0b1101 {
                    let size = (encoding >> 30) & 0x3
                    if size == 0b11, (encoding >> 22) & 0x3 == 0b00 {
                        return LS64Decode.decode(encoding: encoding, address: address)
                    }
                    if size <= 0b01, opHi != 0b1101 {
                        return AtomicExtensionsDecode.decodeRCWNonPair(
                            encoding: encoding, address: address,
                        )
                    }
                }
                // L4b LDAPR OR L13 LSE atomic — discriminate by the LDAPR
                // fixed-bit pattern: bit[23]=1, bit[22]=0, bits[20:16]=11111,
                // bits[15:12]=1100. LSE atomics put (A, R) at bits[23:22] and
                // op at bits[15:12]; an LSE atomic encoding will only collide
                // with LDAPR when A=1 R=0 (= bits[23:22]=10), Rs=ZR (=11111),
                // op=1100 — but op=1100 is in the CAS range, not LSE-RMW range
                // (LSE ops are 0000..1000). So the LDAPR pattern is unique here.
                let bit23 = (encoding >> 23) & 1
                let bit22 = (encoding >> 22) & 1
                let bits20_16 = (encoding >> 16) & 0x1F
                let bits15_12 = (encoding >> 12) & 0xF
                if bit23 == 1, bit22 == 0, bits20_16 == 0x1F, bits15_12 == 0b1100 {
                    return LDAPRDecode.decode(encoding: encoding, address: address)
                }
                return LSEAtomicDecode.decode(encoding: encoding, address: address)
            case 0b10:
                // FEAT_RPRES RPRFM shares the register-offset prefetch cell
                // (size=11, opc=10) with PRFM (register); the discriminator
                // is Rt<4:3> = 11.
                if (encoding >> 30) == 0b11,
                   (encoding >> 22) & 0x3 == 0b10,
                   (encoding >> 3) & 0x3 == 0b11
                {
                    return RangePrefetchDecode.decode(encoding: encoding, address: address)
                }
                return LoadStoreRegisterOffsetDecode.decode(encoding: encoding, address: address)
            // bits[11:10] ∈ {00,01,10,11} all enumerated; {01,11} is `default`
            // — L15 ARM64E LDRAA/LDRAB (01 = signed-offset W=0, 11 = pre-index
            // writeback W=1). ARM64E-only; on plain ARM64 it is unallocated.
            default:
                if !features.contains(.pointerAuthentication) {
                    return .undefined(at: address, encoding: encoding)
                }
                return LDRADecode.decode(encoding: encoding, address: address)
            }

        case 0b111001:
            // L12 — Load/store register, unsigned offset (scaled imm12).
            return LoadStoreUnsignedOffsetDecode.decode(encoding: encoding, address: address)

        default:
            // 0b011001 — op0 ∈ {4, C} at V=0 yields exactly the eight
            // bits[29:24] values enumerated in this switch.
            // This bits[29:24]=0b011001 shell hosts LRCPC2 (LDAPUR/STLUR),
            // MTE L/S, and the v9 atomic/ordered extensions. bit 21 splits
            // the atomic block (1) from LRCPC2 / ordered-pair / GCS (0);
            // bits[11:10] then select the sub-family.
            let bit21 = (encoding >> 21) & 1
            let bits11_10b = (encoding >> 10) & 0x3
            if bit21 == 1 {
                switch bits11_10b {
                case 0b00:
                    // size 00/01: FEAT_LSE128 pair RMW (op 0001/0011/1000) or
                    // FEAT_THE RCW pair (op 1001/1010/1011). size 11: MTE
                    // LDG/LDGM/STGM/STZGM. size 10: unallocated → MTE/undef.
                    let size = (encoding >> 30) & 0x3
                    if size <= 0b01 {
                        if let rcwPair = AtomicExtensionsDecode.decodeRCWPair(
                            encoding: encoding, address: address,
                        ) {
                            return rcwPair
                        }
                        if size == 0b00 {
                            return LSE128Decode.decode(encoding: encoding, address: address)
                        }
                        return .undefined(at: address, encoding: encoding)
                    }
                case 0b01:
                    // FEAT_LSUI unprivileged atomics (size 00/01); size 11 is
                    // MTE STG/STZG/ST2G/STZ2G post-index → falls through to MTE.
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeLSUI(
                            encoding: encoding, address: address,
                        )
                    }
                case 0b10:
                    // FEAT_THE RCW CAS (size 00/01); size 11 is MTE STG/STZG/
                    // ST2G/STZ2G pre-index → falls through to MTE.
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeRCWCas(
                            encoding: encoding, address: address,
                        )
                    }
                // bits[11:10] ∈ {00,01,10,11} all enumerated; 0b11 is `default`.
                default:
                    // FEAT_THE RCW CASP (size 00/01); size 11 is MTE STG/STZG/
                    // ST2G/STZ2G signed-offset → falls through to MTE.
                    if (encoding >> 30) & 0x3 <= 0b01 {
                        return AtomicExtensionsDecode.decodeRCWCasp(
                            encoding: encoding, address: address,
                        )
                    }
                }
                if let mteLS = MemoryTaggingDecode.decodeLS(
                    encoding: encoding, address: address,
                ) {
                    return mteLS
                }
                return .undefined(at: address, encoding: encoding)
            }
            // bit21 == 0.
            switch bits11_10b {
            case 0b10:
                // FEAT_RCPC3 ordered pair (STILP/LDIAPP, bits[23:22] ∈ {00,01})
                // or single-register LDAPR/STLR with writeback (bits[23:22] ∈
                // {10,11}).
                if (encoding >> 22) & 0x3 <= 0b01 {
                    return AtomicExtensionsDecode.decodeRCPC3Pair(
                        encoding: encoding, address: address,
                    )
                }
                return AtomicExtensionsDecode.decodeRCPC3Single(
                    encoding: encoding, address: address,
                )
            case 0b11:
                // FEAT_GCS GCSSTR / GCSSTTR.
                return AtomicExtensionsDecode.decodeGCS(encoding: encoding, address: address)
            // bits[11:10] ∈ {00,01,10,11}; {00,01} is `default` — LRCPC2
            // LDAPUR/STLUR (unscaled imm9, bit10 part of imm9).
            default:
                return LRCPC2Decode.decode(encoding: encoding, address: address)
            }
        }
    }
}

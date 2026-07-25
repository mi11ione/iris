// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SVE2 integer delta at top byte 0x45: widening arith
// (SADDLB…UMULLT), bit-permute (BDEP/BEXT/BGRP) and the interleaved-long
// SADDLBT/SSUBLBT/SSUBLTB, interleaved XOR (EORBT/EORTB), integer matmul
// (SMMLA/UMMLA/USMMLA), absolute-difference accumulate (SABA/…/ADCLB), the
// complex CADD, MATCH/NMATCH, and HISTCNT/HISTSEG. The narrowing and
// shift-immediate families live in SVEIntNarrowDecode.swift.
//
// The sub-dispatch is a specificity-ordered chain of masked compares
// transcribed from the tblgen class signatures (spec preamble: the
// dispatch is built from the machine-generated per-class masks, never by
// hand-transcription of the prose). Several classes nest inside a coarser
// class's region — EORBT/matmul/SSHLL sit inside `sve2_misc`'s (b15=1,b14=0)
// region; CADD/SLI/SSRA sit inside `sve2_int_absdiff_accum`'s (b15=1,b14=1) —
// so the more specific signature is tested first and the order is load-bearing.

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeSVE2High(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        switch e & 0xFFFF_E420 {
        case 0x4531_4000: return decodeMultiVectorExtractNarrow(e, a) // sve2p1_multi_vec_extract_narrow
        default: break
        }
        switch e & 0xFF3E_F800 {
        case 0x4500_D800: return decodeComplexAddition(e, a) // sve2_int_cadd
        default: break
        }
        switch e & 0xFFE0_FC00 {
        case 0x4520_A000: return decodeHistogramSegment(e, a) // sve2_hist_gen_segment
        default: break
        }
        switch e & 0xFFA7_E400 {
        case 0x4520_4000: return decodeSaturatingExtractNarrow(e, a, top: false) // …_bottom
        case 0x4520_4400: return decodeSaturatingExtractNarrow(e, a, top: true) // …_top
        default: break
        }
        switch e & 0xFFE0_C420 {
        case 0x45A0_0000: return decodeMultiVectorShiftNarrow(e, a) // sve2p1_multi_vec_shift_narrow
        default: break
        }
        switch e & 0xFF20_FC00 {
        case 0x4500_9800: return decodeIntegerMatmul(e, a) // sve_int_matmul
        default: break
        }
        switch e & 0xFFA0_F000 {
        case 0x4500_A000: return decodeShiftLeftLong(e, a) // sve2_bitwise_shift_left_long
        default: break
        }
        switch e & 0xFF20_F800 {
        case 0x4500_9000: return decodeXorInterleaved(e, a) // sve2_bitwise_xor_interleaved
        case 0x4500_F000: return decodeShiftInsert(e, a) // sve2_int_bin_shift_imm (SLI/SRI)
        default: break
        }
        switch e & 0xFFA0_E000 {
        case 0x4520_8000: return decodeCharacterMatch(e, a) // sve2_char_match
        case 0x45A0_C000: return decodeHistogramCount(e, a) // sve2_hist_gen_vector
        default: break
        }
        switch e & 0xFF20_E400 {
        case 0x4520_6000: return decodeAddSubNarrowHigh(e, a, top: false) // …_bottom
        case 0x4520_6400: return decodeAddSubNarrowHigh(e, a, top: true) // …_top
        default: break
        }
        switch e & 0xFF20_F000 {
        case 0x4500_E000: return decodeAccumulateShift(e, a) // sve2_int_bin_accum_shift_imm
        default: break
        }
        switch e & 0xFFA0_C400 {
        case 0x4520_0000: return decodeShiftNarrow(e, a, top: false) // …_narrow_bottom
        case 0x4520_0400: return decodeShiftNarrow(e, a, top: true) // …_narrow_top
        default: break
        }
        switch e & 0xFF20_C000 {
        case 0x4500_C000: return decodeAbsoluteDifferenceAccumulate(e, a) // sve2_int_absdiff_accum
        case 0x4500_8000: return decodeMiscellaneous(e, a) // sve2_misc
        default: break
        }
        switch e & 0xFF20_8000 {
        case 0x4500_0000: return decodeWideIntegerArith(e, a) // sve2_wide_int_arith
        default: return undefined(e, a)
        }
    }

    // MARK: sve2_wide_int_arith — widening long / wide / multiply-long (opc [14:10])

    /// The three operand shapes of the widening family: `long` reads both
    /// sources narrow (`Zd.T, Zn.Tb, Zm.Tb`); `wide` reads the first source at
    /// the destination width (`Zd.T, Zn.T, Zm.Tb`); `polynomial` is `long` with
    /// its own size legality (no `.s` destination; a `.q` destination widens
    /// from `.d`).
    enum WideningShape { case long, wide, polynomial }

    @inline(__always)
    static func decodeWideIntegerArith(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let (mnemonic, shape) = wideIntegerArithMnemonic((e >> 10) & 0b11111) else {
            return undefined(e, a)
        }
        let szf = (e >> 22) & 0b11
        // A widening result is one size up from its source, so the .b destination
        // (sz=00) is reserved — `narrower` answers nil for it below — except the
        // polynomial forms, whose sz=00 slot is the .q ← .d widening (and whose
        // .s destination is in turn reserved).
        let dest: ScalarSize
        switch (shape, szf) {
        case (.polynomial, 0): dest = .q
        case (.polynomial, 2): return undefined(e, a)
        default: dest = elementSize(szf)
        }
        guard let source = narrower(dest) else { return undefined(e, a) }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, dest), vec(n, shape == .wide ? dest : source), vec(m, source)],
            scalableEffect: .readsStreamingMode,
        )
    }

    /// opc[14:10] → mnemonic + shape for `sve2_wide_int_arith`. opc 8-11 are
    /// reserved (no instruction claims them).
    @inline(__always)
    static func wideIntegerArithMnemonic(_ opc: UInt32) -> (Mnemonic, WideningShape)? {
        switch opc {
        case 0x00: (.saddlb, .long)
        case 0x01: (.saddlt, .long)
        case 0x02: (.uaddlb, .long)
        case 0x03: (.uaddlt, .long)
        case 0x04: (.ssublb, .long)
        case 0x05: (.ssublt, .long)
        case 0x06: (.usublb, .long)
        case 0x07: (.usublt, .long)
        case 0x0C: (.sabdlb, .long)
        case 0x0D: (.sabdlt, .long)
        case 0x0E: (.uabdlb, .long)
        case 0x0F: (.uabdlt, .long)
        case 0x10: (.saddwb, .wide)
        case 0x11: (.saddwt, .wide)
        case 0x12: (.uaddwb, .wide)
        case 0x13: (.uaddwt, .wide)
        case 0x14: (.ssubwb, .wide)
        case 0x15: (.ssubwt, .wide)
        case 0x16: (.usubwb, .wide)
        case 0x17: (.usubwt, .wide)
        case 0x18: (.sqdmullb, .long)
        case 0x19: (.sqdmullt, .long)
        case 0x1A: (.pmullb, .polynomial)
        case 0x1B: (.pmullt, .polynomial)
        case 0x1C: (.smullb, .long)
        case 0x1D: (.smullt, .long)
        case 0x1E: (.umullb, .long)
        case 0x1F: (.umullt, .long)
        default: nil
        }
    }

    // MARK: sve2_misc — bit-permute (same width) + interleaved-long (widening)

    @inline(__always)
    static func decodeMiscellaneous(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let d = zd(e), n = zn(e), m = zm(e)
        let mnemonic: Mnemonic
        switch (e >> 10) & 0b1111 {
        case 0b1100: mnemonic = .bext
        case 0b1101: mnemonic = .bdep
        case 0b1110: mnemonic = .bgrp
        // The interleaved-long forms widen, so the .b destination is reserved.
        case 0b0000, 0b0010, 0b0011:
            guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
            let long: Mnemonic = switch (e >> 10) & 0b1111 {
            case 0b0000: .saddlbt
            case 0b0010: .ssublbt
            default: .ssubltb // 0b0011
            }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: long,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operands: [vec(d, elementSize(szf)), vec(n, source), vec(m, source)],
                scalableEffect: .readsStreamingMode,
            )
        default: return undefined(e, a)
        }
        return unpredicatedZZZ(e, a, mnemonic: mnemonic, size: elementSize(szf))
    }

    // MARK: sve2_bitwise_xor_interleaved — EORBT / EORTB (destructive, dest read)

    @inline(__always)
    static func decodeXorInterleaved(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let d = zd(e), n = zn(e), m = zm(e), size = sz(e)
        // The odd (EORBT) / even (EORTB) elements of the destination are left
        // unmodified, so Zd is both read and only partially written.
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 10) & 1 == 0 ? .eorbt : .eortb,
            semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), vec(n, size), vec(m, size)],
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: sve2_int_absdiff_accum — SABA/SABAL{,B,T}/ADCL/SBCL (accumulate into Zda)

    /// The absolute-difference-accumulate class straddles both SVE2 top bytes:
    /// b24 (the low bit of the top byte) is part of its opcode. At 0x44 it holds
    /// only the SVE2p2 long forms SABAL/UABAL (opc[13:10] = 01x1, `b11` picking
    /// the signedness); at 0x45 it holds the bottom/top long forms, the
    /// carry-propagating ADCL/SBCL, and the same-width SABA/UABA. Every form
    /// accumulates: Zda is read and every output lane recomputed.
    @inline(__always)
    static func decodeAbsoluteDifferenceAccumulate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let opc = (e >> 10) & 0b1111
        let mnemonic: Mnemonic
        let element: ScalarSize
        let source: ScalarSize

        if (e >> 24) & 1 == 0 { // 0x44 — SABAL / UABAL (long, no bottom/top split)
            guard szf != 0, let narrow = narrower(elementSize(szf)) else { return undefined(e, a) }
            mnemonic = (e >> 11) & 1 == 0 ? .sabal : .uabal
            element = elementSize(szf)
            source = narrow
        } else {
            switch opc {
            case 0b0000, 0b0001, 0b0010, 0b0011: // SABALB/SABALT/UABALB/UABALT (long)
                guard szf != 0, let narrow = narrower(elementSize(szf)) else { return undefined(e, a) }
                mnemonic = switch opc {
                case 0b0000: .sabalb
                case 0b0001: .sabalt
                case 0b0010: .uabalb
                default: .uabalt
                }
                element = elementSize(szf)
                source = narrow
            case 0b0100, 0b0101: // ADCLB/ADCLT (b23=0) and SBCLB/SBCLT (b23=1)
                // Only `.s` and `.d` elements exist here, selected by b22 alone;
                // b23 picks add-with-carry vs subtract-with-carry. The carry is an
                // in-vector value from Zm's odd lanes, never PSTATE.C.
                let top = opc == 0b0101
                mnemonic = (e >> 23) & 1 == 0
                    ? (top ? .adclt : .adclb)
                    : (top ? .sbclt : .sbclb)
                element = (e >> 22) & 1 == 1 ? .d : .s
                source = element
            case 0b1110, 0b1111: // SABA/UABA (same width)
                mnemonic = opc == 0b1110 ? .saba : .uaba
                element = elementSize(szf)
                source = element
            default: return undefined(e, a)
            }
        }

        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [vec(da, element), vec(n, source), vec(m, source)],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve_int_matmul — SMMLA / USMMLA / UMMLA (accumulate, .s ← .b × .b)

    @inline(__always)
    static func decodeIntegerMatmul(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 22) & 0b11 {
        case 0b00: mnemonic = .smmla
        case 0b10: mnemonic = .usmmla
        case 0b11: mnemonic = .ummla
        default: return undefined(e, a) // 0b01 reserved
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [vec(da, .s), vec(n, .b), vec(m, .b)],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_int_bin_accum_shift_imm — SSRA / USRA / SRSRA / URSRA

    @inline(__always)
    static func decodeAccumulateShift(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // The full four-size tsz: tszh = b23:22, tszl:imm3 = b20:16.
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: .ssra
        case 0b01: .usra
        case 0b10: .srsra
        default: .ursra // 0b11
        }
        let da = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [
                vec(da, element), vec(n, element),
                .immediate(value: 2 * Int64(esize) - Int64(tsz), width: 8),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_int_bin_shift_imm — SRI / SLI (bitwise insert)

    @inline(__always)
    static func decodeShiftInsert(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        // SRI shifts right (amount 1…esize), SLI left (0…esize-1). Both leave the
        // vacated destination bits untouched, so Zd survives into the result at
        // statically-known bit positions — a read and a partial write.
        let left = (e >> 10) & 1 == 1
        let amount = left ? Int64(tsz) - Int64(esize) : 2 * Int64(esize) - Int64(tsz)
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: left ? .sli : .sri,
            semanticReads: vecMask(d).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, element), vec(n, element), .immediate(value: amount, width: 8)],
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: sve2_bitwise_shift_left_long — SSHLLB / SSHLLT / USHLLB / USHLLT

    @inline(__always)
    static func decodeShiftLeftLong(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // tsz = b22 : b20:19 : imm3 — its highest set bit names the *source*
        // element (the destination is one size up). A `.d` source would need b23,
        // which this class fixes to 0, so the one-bit tszHigh caps the source
        // at `.s`.
        guard let (source, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 1, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let dest: ScalarSize = source == .b ? .h : source == .h ? .s : .d
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: .sshllb
        case 0b01: .sshllt
        case 0b10: .ushllb
        default: .ushllt // 0b11
        }
        let d = zd(e), n = zn(e)
        // B/T selects which half of the *source* is read; every destination lane
        // is written either way, so this is a full write ( widening row).
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operands: [
                vec(d, dest), vec(n, source),
                .immediate(value: Int64(tsz) - Int64(esize), width: 8),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_int_cadd — CADD / SQCADD (complex addition, ±90° rotation)

    @inline(__always)
    static func decodeComplexAddition(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let dn = zd(e), size = sz(e)
        let m = zn(e) // Zm sits at [9:5] here, not the usual [20:16]
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 16) & 1 == 0 ? .cadd : .sqcadd,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [
                vec(dn, size), vec(dn, size), vec(m, size),
                .immediate(value: (e >> 10) & 1 == 0 ? 90 : 270, width: 16),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_char_match — MATCH / NMATCH (write a predicate AND NZCV)

    @inline(__always)
    static func decodeCharacterMatch(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let pd = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 4) & 1 == 0 ? .match : .nmatch,
            semanticReads: vecMask(n).union(vecMask(m)),
            flagEffect: .nzcv, category: .sve,
            operands: [
                .scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)),
                govern(g, .zeroing), vec(n, size), vec(m, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_hist_gen_vector / _segment — HISTCNT / HISTSEG

    @inline(__always)
    static func decodeHistogramCount(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // Only `.s` and `.d` encode (the class fixes b23=1, so sz is 10 or 11).
        let d = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .histcnt,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), govern(g, .zeroing), vec(n, size), vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeHistogramSegment(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // The sub-dispatch signature already pins sz=00, so HISTSEG is `.b`-only.
        unpredicatedZZZ(e, a, mnemonic: .histseg, size: .b)
    }
}

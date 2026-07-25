// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the non-ZA multi-vector families in cell 110|1|x (top byte
// 0xC1): destructive elementwise ops (bits[15:13]=101), clamp/narrow/permute
// (110), and convert/fmul/frint/unpk (111), plus the SEL exception routed
// from the 100 group. These target vector-register groups `{Zd...}` rather
// than the ZA array. SEL, clamp, the destructive elementwise family, the
// permute (ZIP/UZP/SUNPK/UUNPK) family, the convert/fmul/frint group, the
// narrow-shifts, and the 0xC1 LUTI6 no-ZT0 form are all decoded here from
// generated (mask,value) tables; unmatched words are claimed holes (UNDEFINED).

/// SME2 non-ZA multi-vector decoders.
enum SME2VectorOpsDecode {
    // MARK: - SEL

    /// `SEL {Zd...}, PNg, {Zn...}, {Zm...}` — predicate-governed select.
    @_optimize(speed)
    static func decodeSel(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let fourWay = e & 0x0001_0000 != 0
        let count: UInt8 = fourWay ? 4 : 2
        let element = sizeElement(e)
        let (zd, zn, zm): (UInt8, UInt8, UInt8) = fourWay
            ? (UInt8(e & 0x1C), UInt8((e >> 5) & 0x1C), UInt8((e >> 16) & 0x1C))
            : (UInt8(e & 0x1E), UInt8((e >> 5) & 0x1E), UInt8((e >> 16) & 0x1E))
        let pn = UInt8((e >> 10) & 0x7)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .sel,
            semanticReads: SME2Decode.groupMask(zn, count).union(SME2Decode.groupMask(zm, count)),
            semanticWrites: SME2Decode.groupMask(zd, count),
            category: .sme,
            operands: [
                SME2Decode.group(zd, count, element),
                .scalablePredicate(ScalablePredicateRef(
                    registerIndex: 8 &+ pn, role: .governing, isCounter: true,
                )),
                SME2Decode.group(zn, count, element),
                SME2Decode.group(zm, count, element),
            ],
            scalableReads: SME2Decode.predMask(8 &+ pn),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: - clamp

    /// Decode a clamp word `{Zd...}, Zn, Zm` (SCLAMP/UCLAMP/FCLAMP/BFCLAMP),
    /// or a 2-way permute (ZIP/UZP), else route onward. Called from the 110
    /// (clamp/narrow/permute) group.
    @_optimize(speed)
    static func decodeClampNarrowPermute(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if let d = decodeClamp(e, a) { return d }
        if let d = decodePermute(e, a) { return d }
        if let d = decodeNarrowShift2(e, a) { return d }
        if let d = decodeNarrowShift4(e, a) { return d }
        return SME2Decode.undefined(e, a)
    }

    /// 4-way saturating rounding shift-right narrow: `Zd.<T>, {Zn×4}, #const`.
    /// `tsize:imm5` (bits[23:22]:[20:16]) is the 7-bit shift field; `tsize==01`
    /// gives `.b`←`.s` (const = 64 − field), `tsize>=10` gives `.h`←`.d`
    /// (const = 128 − field). `op`(bit6)/`U`(bit5)/`N`(bit10) pick the variant.
    @inline(__always)
    private static func decodeNarrowShift4(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        guard e & 0xFF20_F800 == 0xC120_D800 else { return nil }
        let tsize = UInt8((e >> 22) & 0x3)
        guard tsize != 0 else { return nil } // tsize=00 reserved
        let narrow = e & 0x400 != 0
        let mnemonic: Mnemonic
        switch (e >> 5) & 0x3 { // op(bit6):U(bit5)
        case 0b00: mnemonic = narrow ? .sqrshrn : .sqrshr
        case 0b01: mnemonic = narrow ? .uqrshrn : .uqrshr
        case 0b10: mnemonic = narrow ? .sqrshrun : .sqrshru
        default: return nil // op=1,U=1 unallocated
        }
        let dst: ScalarSize = tsize == 1 ? .b : .h
        let src: ScalarSize = tsize == 1 ? .s : .d
        let field = (UInt32(tsize) << 5) | ((e >> 16) & 0x1F)
        let shift = (dst == .b ? Int64(64) : 128) - Int64(field)
        let zd = SME2Decode.zd5(e)
        let zn = UInt8((e >> 7) & 0x7) &* 4
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: SME2Decode.groupMask(zn, 4),
            semanticWrites: SME2Decode.vecMask(zd),
            category: .sme,
            operands: [
                SME2Decode.vec(zd, dst),
                SME2Decode.group(zn, 4, src),
                .immediate(value: shift, width: 7),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    /// 2-way saturating rounding shift-right narrow: `Zd.h, {Zn.s, Zn+1.s},
    /// #const` where `const = 16 - imm4` (`imm4 == 0` → `#16`).
    @inline(__always)
    private static func decodeNarrowShift2(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        let mnemonic: Mnemonic
        // Zn is bits[9:6] (a pair), so bit6 must stay free in the match mask.
        switch e & 0xFFF0_FC20 {
        case 0xC1E0_D400: mnemonic = .sqrshr
        case 0xC1E0_D420: mnemonic = .uqrshr
        case 0xC1F0_D400: mnemonic = .sqrshru
        default: return nil
        }
        let zd = SME2Decode.zd5(e)
        let zn = UInt8((e >> 6) & 0xF) &* 2
        let shift = 16 - Int64((e >> 16) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: SME2Decode.groupMask(zn, 2),
            semanticWrites: SME2Decode.vecMask(zd),
            category: .sme,
            operands: [
                SME2Decode.vec(zd, .h),
                SME2Decode.group(zn, 2, .s),
                .immediate(value: shift, width: 6),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: - permute (ZIP/UZP/SUNPK/UUNPK)

    /// ZIP/UZP (2-way `{Zd}, Zn, Zm`; 4-way `{Zd}, {Zn}`) and SUNPK/UUNPK
    /// (2-way `{Zd}, Zn`; 4-way `{Zd}, {Zn}`). Shared by the 110 (2-way) and
    /// 111 (4-way / unpk) groups; returns `nil` for a non-permute word.
    @inline(__always)
    private static func decodePermute(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        // The size field (bits[23:22]) is fixed per tblgen record, so the
        // masks below strip it (and the .q / op selector bits) to match one
        // opcode across all element sizes.
        // 2-way ZIP/UZP: `{Zd×2}, Zn, Zm` — two single full-range sources. The
        // b/h/s/d forms fix bit10=0 (bit10=1 belongs to the narrow-shift
        // opcode); the `.q` form is size-00-only, so its size bits are fixed.
        if e & 0xFF20_FC00 == 0xC120_D000 || e & 0xFFE0_FC00 == 0xC120_D400 {
            let element: ScalarSize = e & 0x400 != 0 ? .q : sizeElement(e)
            let zd = UInt8(e & 0x1E)
            let zn = UInt8((e >> 5) & 0x1F)
            let zm = UInt8((e >> 16) & 0x1F)
            return permuteDraft(
                e, a, e & 0x1 != 0 ? .uzp : .zip,
                dest: SME2Decode.group(zd, 2, element), destFirst: zd, destCount: 2,
                operands: [SME2Decode.vec(zn, element), SME2Decode.vec(zm, element)],
                reads: SME2Decode.vecMask(zn).union(SME2Decode.vecMask(zm)),
            )
        }
        // 4-way ZIP/UZP: `{Zd×4}, {Zn×4}`. bit16=1 selects `.q`, valid only at
        // size 00; a bit16=1 word at another size is a reserved hole.
        if e & 0xFF3E_FC61 == 0xC136_E000, e & 0x10000 == 0 || (e >> 22) & 0x3 == 0 {
            let element = permuteQElement(e)
            let zd = UInt8(e & 0x1C)
            let zn = UInt8((e >> 5) & 0x1C)
            return permuteDraft(
                e, a, e & 0x2 != 0 ? .uzp : .zip,
                dest: SME2Decode.group(zd, 4, element), destFirst: zd, destCount: 4,
                operands: [SME2Decode.group(zn, 4, element)],
                reads: SME2Decode.groupMask(zn, 4),
            )
        }
        // 2-way SUNPK/UUNPK: `{Zd×2}, Zn.<Tb>` (source is the narrower half).
        // Size 00 (`.b` dest) is reserved — there is no narrower source.
        if e & 0xFF3F_FC00 == 0xC125_E000, (e >> 22) & 0x3 != 0 {
            let dst = sizeElement(e)
            let zd = UInt8(e & 0x1E)
            let zn = UInt8((e >> 5) & 0x1F)
            return permuteDraft(
                e, a, e & 0x1 != 0 ? .uunpk : .sunpk,
                dest: SME2Decode.group(zd, 2, dst), destFirst: zd, destCount: 2,
                operands: [SME2Decode.vec(zn, halfElement(dst))],
                reads: SME2Decode.vecMask(zn),
            )
        }
        // 4-way SUNPK/UUNPK: `{Zd×4}, {Zn×2}` (size 00 reserved).
        if e & 0xFF3F_FC22 == 0xC135_E000, (e >> 22) & 0x3 != 0 {
            let dst = sizeElement(e)
            let zd = UInt8(e & 0x1C)
            let zn = UInt8((e >> 5) & 0x1E)
            return permuteDraft(
                e, a, e & 0x1 != 0 ? .uunpk : .sunpk,
                dest: SME2Decode.group(zd, 4, dst), destFirst: zd, destCount: 4,
                operands: [SME2Decode.group(zn, 2, halfElement(dst))],
                reads: SME2Decode.groupMask(zn, 2),
            )
        }
        return nil
    }

    @inline(__always)
    private static func permuteDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, dest: Operand,
        destFirst: UInt8, destCount: UInt8, operands: [Operand], reads: RegisterSet,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: SME2Decode.groupMask(destFirst, destCount),
            category: .sme, operands: [dest] + operands,
            scalableEffect: .readsStreamingMode,
        )
    }

    /// Element of a 4-way ZIP/UZP — size 00 is `.b` (bit16=0) or `.q` (bit16=1).
    @inline(__always)
    private static func permuteQElement(_ e: UInt32) -> ScalarSize {
        (e >> 22) & 0x3 == 0 ? (e & 0x10000 != 0 ? .q : .b) : sizeElement(e)
    }

    /// The narrower half of an unpack destination element. The unpack
    /// destination is always `.h`/`.s`/`.d` (a `.b` destination is reserved),
    /// so `.d` and the unreached wider sizes share the `.s` default.
    @inline(__always)
    private static func halfElement(_ s: ScalarSize) -> ScalarSize {
        switch s { case .h: .b; case .s: .h; default: .s }
    }

    @inline(__always)
    private static func decodeClamp(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        // 2x: (ff20fc01, c120c400 sclamp / c120c401 uclamp / c120c000 fclamp),
        // 4x: +0x800. bf clamp fixes size=00 with mask ffe0fc0x.
        let fourWay = e & 0x800 != 0
        let count: UInt8 = fourWay ? 4 : 2
        let mnemonic: Mnemonic
        let element: ScalarSize
        switch e & (fourWay ? 0xFF20_FC03 : 0xFF20_FC01) {
        case 0xC120_C400, 0xC120_CC00:
            mnemonic = .sclamp; element = sizeElement(e)
        case 0xC120_C401, 0xC120_CC01:
            mnemonic = .uclamp; element = sizeElement(e)
        case 0xC120_C000, 0xC120_C800:
            // FCLAMP (h/s/d) or BFCLAMP (size=00 twin).
            if (e >> 22) & 0x3 == 0 {
                mnemonic = .bfclamp; element = .h
            } else {
                mnemonic = .fclamp; element = sizeElement(e)
            }
        default:
            return nil
        }
        let zd = fourWay ? UInt8(e & 0x1C) : UInt8(e & 0x1E)
        let zn = UInt8((e >> 5) & 0x1F)
        let zm = UInt8((e >> 16) & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: SME2Decode.groupMask(zd, count)
                .union(SME2Decode.vecMask(zn)).union(SME2Decode.vecMask(zm)),
            semanticWrites: SME2Decode.groupMask(zd, count),
            category: .sme,
            operands: [
                SME2Decode.group(zd, count, element),
                SME2Decode.vec(zn, element),
                SME2Decode.vec(zm, element),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: - destructive / convert

    /// A destructive elementwise record identity (mnemonic, group width,
    /// whether the second source is a multi-vector list, element size).
    private struct DestrSpec {
        let mnemonic: Mnemonic
        let vg: UInt8
        let zzw: Bool
        let element: ScalarSize
        init(_ mnemonic: Mnemonic, vg: UInt8, zzw: Bool, element: ScalarSize) {
            self.mnemonic = mnemonic; self.vg = vg; self.zzw = zzw; self.element = element
        }
    }

    /// Destructive elementwise ops (bits[15:13]=101): `{Zdn}, {Zdn}, Zm` (zzv,
    /// single broadcast `Zm`) or `{Zdn}, {Zdn}, {Zm}` (zzw, multi `Zm`). The
    /// destination is tied to the first source. Decoded from the generated
    /// (mask,value) table below (transcribed from the investigation records).
    @_optimize(speed)
    static func decodeDestructive(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let spec = destructiveSpec(e) else { return SME2Decode.undefined(e, a) }
        let zdn = spec.vg == 4 ? UInt8((e >> 2) & 0x7) &* 4 : UInt8((e >> 1) & 0xF) &* 2
        let dest = SME2Decode.group(zdn, spec.vg, spec.element)
        let src2: Operand
        let src2Reads: RegisterSet
        if spec.zzw {
            let zm = spec.vg == 4 ? UInt8((e >> 18) & 0x7) &* 4 : UInt8((e >> 17) & 0xF) &* 2
            src2 = SME2Decode.group(zm, spec.vg, spec.element)
            src2Reads = SME2Decode.groupMask(zm, spec.vg)
        } else {
            let zm = SME2Decode.zm4(e)
            src2 = SME2Decode.vec(zm, spec.element)
            src2Reads = SME2Decode.vecMask(zm)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: spec.mnemonic,
            semanticReads: SME2Decode.groupMask(zdn, spec.vg).union(src2Reads),
            semanticWrites: SME2Decode.groupMask(zdn, spec.vg),
            category: .sme,
            operands: [dest, SME2Decode.group(zdn, spec.vg, spec.element), src2],
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    private static func destructiveSpec(_ e: UInt32) -> DestrSpec? {
        switch e & 0xFFE3_FFE3 {
        case 0xC120_B800: return DestrSpec(.smax, vg: 4, zzw: true, element: .b)
        case 0xC120_B801: return DestrSpec(.umax, vg: 4, zzw: true, element: .b)
        case 0xC120_B820: return DestrSpec(.smin, vg: 4, zzw: true, element: .b)
        case 0xC120_B821: return DestrSpec(.umin, vg: 4, zzw: true, element: .b)
        case 0xC120_B900: return DestrSpec(.bfmax, vg: 4, zzw: true, element: .h)
        case 0xC120_B901: return DestrSpec(.bfmin, vg: 4, zzw: true, element: .h)
        case 0xC120_B920: return DestrSpec(.bfmaxnm, vg: 4, zzw: true, element: .h)
        case 0xC120_B921: return DestrSpec(.bfminnm, vg: 4, zzw: true, element: .h)
        case 0xC120_B980: return DestrSpec(.bfscale, vg: 4, zzw: true, element: .h)
        case 0xC120_BA20: return DestrSpec(.srshl, vg: 4, zzw: true, element: .b)
        case 0xC120_BA21: return DestrSpec(.urshl, vg: 4, zzw: true, element: .b)
        case 0xC120_BC00: return DestrSpec(.sqdmulh, vg: 4, zzw: true, element: .b)
        case 0xC160_B800: return DestrSpec(.smax, vg: 4, zzw: true, element: .h)
        case 0xC160_B801: return DestrSpec(.umax, vg: 4, zzw: true, element: .h)
        case 0xC160_B820: return DestrSpec(.smin, vg: 4, zzw: true, element: .h)
        case 0xC160_B821: return DestrSpec(.umin, vg: 4, zzw: true, element: .h)
        case 0xC160_B900: return DestrSpec(.fmax, vg: 4, zzw: true, element: .h)
        case 0xC160_B901: return DestrSpec(.fmin, vg: 4, zzw: true, element: .h)
        case 0xC160_B920: return DestrSpec(.fmaxnm, vg: 4, zzw: true, element: .h)
        case 0xC160_B921: return DestrSpec(.fminnm, vg: 4, zzw: true, element: .h)
        case 0xC160_B940: return DestrSpec(.famax, vg: 4, zzw: true, element: .h)
        case 0xC160_B941: return DestrSpec(.famin, vg: 4, zzw: true, element: .h)
        case 0xC160_B980: return DestrSpec(.fscale, vg: 4, zzw: true, element: .h)
        case 0xC160_BA20: return DestrSpec(.srshl, vg: 4, zzw: true, element: .h)
        case 0xC160_BA21: return DestrSpec(.urshl, vg: 4, zzw: true, element: .h)
        case 0xC160_BC00: return DestrSpec(.sqdmulh, vg: 4, zzw: true, element: .h)
        case 0xC1A0_B800: return DestrSpec(.smax, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B801: return DestrSpec(.umax, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B820: return DestrSpec(.smin, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B821: return DestrSpec(.umin, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B900: return DestrSpec(.fmax, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B901: return DestrSpec(.fmin, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B920: return DestrSpec(.fmaxnm, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B921: return DestrSpec(.fminnm, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B940: return DestrSpec(.famax, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B941: return DestrSpec(.famin, vg: 4, zzw: true, element: .s)
        case 0xC1A0_B980: return DestrSpec(.fscale, vg: 4, zzw: true, element: .s)
        case 0xC1A0_BA20: return DestrSpec(.srshl, vg: 4, zzw: true, element: .s)
        case 0xC1A0_BA21: return DestrSpec(.urshl, vg: 4, zzw: true, element: .s)
        case 0xC1A0_BC00: return DestrSpec(.sqdmulh, vg: 4, zzw: true, element: .s)
        case 0xC1E0_B800: return DestrSpec(.smax, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B801: return DestrSpec(.umax, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B820: return DestrSpec(.smin, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B821: return DestrSpec(.umin, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B900: return DestrSpec(.fmax, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B901: return DestrSpec(.fmin, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B920: return DestrSpec(.fmaxnm, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B921: return DestrSpec(.fminnm, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B940: return DestrSpec(.famax, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B941: return DestrSpec(.famin, vg: 4, zzw: true, element: .d)
        case 0xC1E0_B980: return DestrSpec(.fscale, vg: 4, zzw: true, element: .d)
        case 0xC1E0_BA20: return DestrSpec(.srshl, vg: 4, zzw: true, element: .d)
        case 0xC1E0_BA21: return DestrSpec(.urshl, vg: 4, zzw: true, element: .d)
        case 0xC1E0_BC00: return DestrSpec(.sqdmulh, vg: 4, zzw: true, element: .d)
        default: break
        }
        switch e & 0xFFF0_FFE3 {
        case 0xC120_A800: return DestrSpec(.smax, vg: 4, zzw: false, element: .b)
        case 0xC120_A801: return DestrSpec(.umax, vg: 4, zzw: false, element: .b)
        case 0xC120_A820: return DestrSpec(.smin, vg: 4, zzw: false, element: .b)
        case 0xC120_A821: return DestrSpec(.umin, vg: 4, zzw: false, element: .b)
        case 0xC120_A900: return DestrSpec(.bfmax, vg: 4, zzw: false, element: .h)
        case 0xC120_A901: return DestrSpec(.bfmin, vg: 4, zzw: false, element: .h)
        case 0xC120_A920: return DestrSpec(.bfmaxnm, vg: 4, zzw: false, element: .h)
        case 0xC120_A921: return DestrSpec(.bfminnm, vg: 4, zzw: false, element: .h)
        case 0xC120_A980: return DestrSpec(.bfscale, vg: 4, zzw: false, element: .h)
        case 0xC120_AA20: return DestrSpec(.srshl, vg: 4, zzw: false, element: .b)
        case 0xC120_AA21: return DestrSpec(.urshl, vg: 4, zzw: false, element: .b)
        case 0xC120_AB00: return DestrSpec(.add, vg: 4, zzw: false, element: .b)
        case 0xC120_AC00: return DestrSpec(.sqdmulh, vg: 4, zzw: false, element: .b)
        case 0xC160_A800: return DestrSpec(.smax, vg: 4, zzw: false, element: .h)
        case 0xC160_A801: return DestrSpec(.umax, vg: 4, zzw: false, element: .h)
        case 0xC160_A820: return DestrSpec(.smin, vg: 4, zzw: false, element: .h)
        case 0xC160_A821: return DestrSpec(.umin, vg: 4, zzw: false, element: .h)
        case 0xC160_A900: return DestrSpec(.fmax, vg: 4, zzw: false, element: .h)
        case 0xC160_A901: return DestrSpec(.fmin, vg: 4, zzw: false, element: .h)
        case 0xC160_A920: return DestrSpec(.fmaxnm, vg: 4, zzw: false, element: .h)
        case 0xC160_A921: return DestrSpec(.fminnm, vg: 4, zzw: false, element: .h)
        case 0xC160_A980: return DestrSpec(.fscale, vg: 4, zzw: false, element: .h)
        case 0xC160_AA20: return DestrSpec(.srshl, vg: 4, zzw: false, element: .h)
        case 0xC160_AA21: return DestrSpec(.urshl, vg: 4, zzw: false, element: .h)
        case 0xC160_AB00: return DestrSpec(.add, vg: 4, zzw: false, element: .h)
        case 0xC160_AC00: return DestrSpec(.sqdmulh, vg: 4, zzw: false, element: .h)
        case 0xC1A0_A800: return DestrSpec(.smax, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A801: return DestrSpec(.umax, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A820: return DestrSpec(.smin, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A821: return DestrSpec(.umin, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A900: return DestrSpec(.fmax, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A901: return DestrSpec(.fmin, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A920: return DestrSpec(.fmaxnm, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A921: return DestrSpec(.fminnm, vg: 4, zzw: false, element: .s)
        case 0xC1A0_A980: return DestrSpec(.fscale, vg: 4, zzw: false, element: .s)
        case 0xC1A0_AA20: return DestrSpec(.srshl, vg: 4, zzw: false, element: .s)
        case 0xC1A0_AA21: return DestrSpec(.urshl, vg: 4, zzw: false, element: .s)
        case 0xC1A0_AB00: return DestrSpec(.add, vg: 4, zzw: false, element: .s)
        case 0xC1A0_AC00: return DestrSpec(.sqdmulh, vg: 4, zzw: false, element: .s)
        case 0xC1E0_A800: return DestrSpec(.smax, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A801: return DestrSpec(.umax, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A820: return DestrSpec(.smin, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A821: return DestrSpec(.umin, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A900: return DestrSpec(.fmax, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A901: return DestrSpec(.fmin, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A920: return DestrSpec(.fmaxnm, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A921: return DestrSpec(.fminnm, vg: 4, zzw: false, element: .d)
        case 0xC1E0_A980: return DestrSpec(.fscale, vg: 4, zzw: false, element: .d)
        case 0xC1E0_AA20: return DestrSpec(.srshl, vg: 4, zzw: false, element: .d)
        case 0xC1E0_AA21: return DestrSpec(.urshl, vg: 4, zzw: false, element: .d)
        case 0xC1E0_AB00: return DestrSpec(.add, vg: 4, zzw: false, element: .d)
        case 0xC1E0_AC00: return DestrSpec(.sqdmulh, vg: 4, zzw: false, element: .d)
        default: break
        }
        switch e & 0xFFE1_FFE1 {
        case 0xC120_B000: return DestrSpec(.smax, vg: 2, zzw: true, element: .b)
        case 0xC120_B001: return DestrSpec(.umax, vg: 2, zzw: true, element: .b)
        case 0xC120_B020: return DestrSpec(.smin, vg: 2, zzw: true, element: .b)
        case 0xC120_B021: return DestrSpec(.umin, vg: 2, zzw: true, element: .b)
        case 0xC120_B100: return DestrSpec(.bfmax, vg: 2, zzw: true, element: .h)
        case 0xC120_B101: return DestrSpec(.bfmin, vg: 2, zzw: true, element: .h)
        case 0xC120_B120: return DestrSpec(.bfmaxnm, vg: 2, zzw: true, element: .h)
        case 0xC120_B121: return DestrSpec(.bfminnm, vg: 2, zzw: true, element: .h)
        case 0xC120_B180: return DestrSpec(.bfscale, vg: 2, zzw: true, element: .h)
        case 0xC120_B220: return DestrSpec(.srshl, vg: 2, zzw: true, element: .b)
        case 0xC120_B221: return DestrSpec(.urshl, vg: 2, zzw: true, element: .b)
        case 0xC120_B400: return DestrSpec(.sqdmulh, vg: 2, zzw: true, element: .b)
        case 0xC160_B000: return DestrSpec(.smax, vg: 2, zzw: true, element: .h)
        case 0xC160_B001: return DestrSpec(.umax, vg: 2, zzw: true, element: .h)
        case 0xC160_B020: return DestrSpec(.smin, vg: 2, zzw: true, element: .h)
        case 0xC160_B021: return DestrSpec(.umin, vg: 2, zzw: true, element: .h)
        case 0xC160_B100: return DestrSpec(.fmax, vg: 2, zzw: true, element: .h)
        case 0xC160_B101: return DestrSpec(.fmin, vg: 2, zzw: true, element: .h)
        case 0xC160_B120: return DestrSpec(.fmaxnm, vg: 2, zzw: true, element: .h)
        case 0xC160_B121: return DestrSpec(.fminnm, vg: 2, zzw: true, element: .h)
        case 0xC160_B140: return DestrSpec(.famax, vg: 2, zzw: true, element: .h)
        case 0xC160_B141: return DestrSpec(.famin, vg: 2, zzw: true, element: .h)
        case 0xC160_B180: return DestrSpec(.fscale, vg: 2, zzw: true, element: .h)
        case 0xC160_B220: return DestrSpec(.srshl, vg: 2, zzw: true, element: .h)
        case 0xC160_B221: return DestrSpec(.urshl, vg: 2, zzw: true, element: .h)
        case 0xC160_B400: return DestrSpec(.sqdmulh, vg: 2, zzw: true, element: .h)
        case 0xC1A0_B000: return DestrSpec(.smax, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B001: return DestrSpec(.umax, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B020: return DestrSpec(.smin, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B021: return DestrSpec(.umin, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B100: return DestrSpec(.fmax, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B101: return DestrSpec(.fmin, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B120: return DestrSpec(.fmaxnm, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B121: return DestrSpec(.fminnm, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B140: return DestrSpec(.famax, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B141: return DestrSpec(.famin, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B180: return DestrSpec(.fscale, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B220: return DestrSpec(.srshl, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B221: return DestrSpec(.urshl, vg: 2, zzw: true, element: .s)
        case 0xC1A0_B400: return DestrSpec(.sqdmulh, vg: 2, zzw: true, element: .s)
        case 0xC1E0_B000: return DestrSpec(.smax, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B001: return DestrSpec(.umax, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B020: return DestrSpec(.smin, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B021: return DestrSpec(.umin, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B100: return DestrSpec(.fmax, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B101: return DestrSpec(.fmin, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B120: return DestrSpec(.fmaxnm, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B121: return DestrSpec(.fminnm, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B140: return DestrSpec(.famax, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B141: return DestrSpec(.famin, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B180: return DestrSpec(.fscale, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B220: return DestrSpec(.srshl, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B221: return DestrSpec(.urshl, vg: 2, zzw: true, element: .d)
        case 0xC1E0_B400: return DestrSpec(.sqdmulh, vg: 2, zzw: true, element: .d)
        default: break
        }
        switch e & 0xFFF0_FFE1 {
        case 0xC120_A000: return DestrSpec(.smax, vg: 2, zzw: false, element: .b)
        case 0xC120_A001: return DestrSpec(.umax, vg: 2, zzw: false, element: .b)
        case 0xC120_A020: return DestrSpec(.smin, vg: 2, zzw: false, element: .b)
        case 0xC120_A021: return DestrSpec(.umin, vg: 2, zzw: false, element: .b)
        case 0xC120_A100: return DestrSpec(.bfmax, vg: 2, zzw: false, element: .h)
        case 0xC120_A101: return DestrSpec(.bfmin, vg: 2, zzw: false, element: .h)
        case 0xC120_A120: return DestrSpec(.bfmaxnm, vg: 2, zzw: false, element: .h)
        case 0xC120_A121: return DestrSpec(.bfminnm, vg: 2, zzw: false, element: .h)
        case 0xC120_A180: return DestrSpec(.bfscale, vg: 2, zzw: false, element: .h)
        case 0xC120_A220: return DestrSpec(.srshl, vg: 2, zzw: false, element: .b)
        case 0xC120_A221: return DestrSpec(.urshl, vg: 2, zzw: false, element: .b)
        case 0xC120_A300: return DestrSpec(.add, vg: 2, zzw: false, element: .b)
        case 0xC120_A400: return DestrSpec(.sqdmulh, vg: 2, zzw: false, element: .b)
        case 0xC160_A000: return DestrSpec(.smax, vg: 2, zzw: false, element: .h)
        case 0xC160_A001: return DestrSpec(.umax, vg: 2, zzw: false, element: .h)
        case 0xC160_A020: return DestrSpec(.smin, vg: 2, zzw: false, element: .h)
        case 0xC160_A021: return DestrSpec(.umin, vg: 2, zzw: false, element: .h)
        case 0xC160_A100: return DestrSpec(.fmax, vg: 2, zzw: false, element: .h)
        case 0xC160_A101: return DestrSpec(.fmin, vg: 2, zzw: false, element: .h)
        case 0xC160_A120: return DestrSpec(.fmaxnm, vg: 2, zzw: false, element: .h)
        case 0xC160_A121: return DestrSpec(.fminnm, vg: 2, zzw: false, element: .h)
        case 0xC160_A180: return DestrSpec(.fscale, vg: 2, zzw: false, element: .h)
        case 0xC160_A220: return DestrSpec(.srshl, vg: 2, zzw: false, element: .h)
        case 0xC160_A221: return DestrSpec(.urshl, vg: 2, zzw: false, element: .h)
        case 0xC160_A300: return DestrSpec(.add, vg: 2, zzw: false, element: .h)
        case 0xC160_A400: return DestrSpec(.sqdmulh, vg: 2, zzw: false, element: .h)
        case 0xC1A0_A000: return DestrSpec(.smax, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A001: return DestrSpec(.umax, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A020: return DestrSpec(.smin, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A021: return DestrSpec(.umin, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A100: return DestrSpec(.fmax, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A101: return DestrSpec(.fmin, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A120: return DestrSpec(.fmaxnm, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A121: return DestrSpec(.fminnm, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A180: return DestrSpec(.fscale, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A220: return DestrSpec(.srshl, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A221: return DestrSpec(.urshl, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A300: return DestrSpec(.add, vg: 2, zzw: false, element: .s)
        case 0xC1A0_A400: return DestrSpec(.sqdmulh, vg: 2, zzw: false, element: .s)
        case 0xC1E0_A000: return DestrSpec(.smax, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A001: return DestrSpec(.umax, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A020: return DestrSpec(.smin, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A021: return DestrSpec(.umin, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A100: return DestrSpec(.fmax, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A101: return DestrSpec(.fmin, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A120: return DestrSpec(.fmaxnm, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A121: return DestrSpec(.fminnm, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A180: return DestrSpec(.fscale, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A220: return DestrSpec(.srshl, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A221: return DestrSpec(.urshl, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A300: return DestrSpec(.add, vg: 2, zzw: false, element: .d)
        case 0xC1E0_A400: return DestrSpec(.sqdmulh, vg: 2, zzw: false, element: .d)
        default: break
        }
        return nil
    }

    /// The operand shape of a convert/fmul record.
    private enum CvtShape { case narrow, widen, same, fmul }

    /// A convert/fmul record identity.
    private struct CvtSpec {
        let mnemonic: Mnemonic
        let shape: CvtShape
        let count: UInt8
        let dst: ScalarSize
        let src: ScalarSize
        let sub: String
        init(_ mnemonic: Mnemonic, shape: CvtShape, count: UInt8, dst: ScalarSize, src: ScalarSize, sub: String) {
            self.mnemonic = mnemonic; self.shape = shape; self.count = count
            self.dst = dst; self.src = src; self.sub = sub
        }
    }

    /// Convert / FMUL / FRINT (bits[15:13]=111), plus the 4-way permute / unpk
    /// forms. The convert family targets vector groups in four shapes: narrow
    /// (`Zd, {Zn}`), widen (`{Zd}, Zn`), same-count (`{Zd}, {Zn}`), and FMUL
    /// (`{Zd}, {Zn}, Zm|{Zm}`). Decoded from the generated table below.
    @_optimize(speed)
    static func decodeConvertMisc(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if let d = decodePermute(e, a) { return d }
        if let d = decodeLuti6ZmZ2(e, a) { return d }
        guard let spec = convertSpec(e) else { return SME2Decode.undefined(e, a) }
        return buildConvert(e, a, spec)
    }

    /// The `0xC1` LUTI6 no-`ZT0` form: `luti6 {Zd×4}.h, {Zn, Zn+1}.h,
    /// {Zm, Zm+1}[i]` — the table is a `.h` `Zn` pair (mod-32) and the source
    /// a suffix-less `Zm` pair (mod-32) with a group index (`i1`, bit22).
    /// Consecutive (`c120f400`) or `.S`-strided (`c120fc00`) destination.
    @inline(__always)
    private static func decodeLuti6ZmZ2(_ e: UInt32, _ a: UInt64) -> DecodedDraft? {
        let strided: Bool
        if e & 0xFFA0_FC03 == 0xC120_F400 { strided = false }
        else if e & 0xFFA0_FC0C == 0xC120_FC00 { strided = true }
        else { return nil }
        let index = UInt8((e >> 22) & 0x1)
        let zn = UInt8((e >> 5) & 0x1F)
        let zm = UInt8((e >> 16) & 0x1F)
        let zdFirst: UInt8 = strided
            ? UInt8((e >> 4) & 0x1) &* 16 &+ UInt8(e & 0x3)
            : UInt8(e & 0x1C)
        let table = ScalableVectorGroup(firstIndex: zn, count: 2, element: .h, layout: .consecutive)
        let source = ScalableVectorGroup(
            firstIndex: zm, count: 2, element: nil, layout: .consecutive, elementIndex: index,
        )
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .luti6,
            semanticReads: SME2Decode.groupMask(zn, 2).union(SME2Decode.groupMask(zm, 2)),
            semanticWrites: SME2Decode.groupMask(zdFirst, 4, strided: strided),
            category: .sme,
            operands: [
                SME2Decode.group(zdFirst, 4, .h, strided: strided),
                .scalableVectorGroup(table),
                .scalableVectorGroup(source),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    private static func buildConvert(_ e: UInt32, _ a: UInt64, _ spec: CvtSpec) -> DecodedDraft {
        let n = spec.count
        let gd = n == 4 ? UInt8(e & 0x1C) : UInt8(e & 0x1E)
        let gn = n == 4 ? UInt8((e >> 7) & 0x7) &* 4 : UInt8((e >> 6) & 0xF) &* 2
        let sd = SME2Decode.zd5(e)
        let sn = UInt8((e >> 5) & 0x1F)
        switch spec.shape {
        case .narrow: // Zd.<dst>, {Zn x count}
            return convertDraft(e, a, spec.mnemonic,
                                operands: [SME2Decode.vec(sd, spec.dst), SME2Decode.group(gn, n, spec.src)],
                                reads: SME2Decode.groupMask(gn, n), writes: SME2Decode.vecMask(sd))
        case .widen: // {Zd x count}, Zn.<src>
            return convertDraft(e, a, spec.mnemonic,
                                operands: [SME2Decode.group(gd, n, spec.dst), SME2Decode.vec(sn, spec.src)],
                                reads: SME2Decode.vecMask(sn), writes: SME2Decode.groupMask(gd, n))
        case .same: // {Zd x count}, {Zn x count}
            return convertDraft(e, a, spec.mnemonic,
                                operands: [SME2Decode.group(gd, n, spec.dst), SME2Decode.group(gn, n, spec.src)],
                                reads: SME2Decode.groupMask(gn, n), writes: SME2Decode.groupMask(gd, n))
        case .fmul: // {Zd}, {Zn}, Zm | {Zm}
            // FMUL's broadcast Zm is bits[20:17] (z0-z15), not the bits[19:16]
            // of the destructive broadcast forms.
            let zmSingle = UInt8((e >> 17) & 0xF)
            let zmGroup = n == 4 ? UInt8((e >> 18) & 0x7) &* 4 : UInt8((e >> 17) & 0xF) &* 2
            let src2: Operand = spec.sub == "zzw" ? SME2Decode.group(zmGroup, n, spec.src) : SME2Decode.vec(zmSingle, spec.src)
            let src2Reads = spec.sub == "zzw" ? SME2Decode.groupMask(zmGroup, n) : SME2Decode.vecMask(zmSingle)
            return convertDraft(e, a, spec.mnemonic,
                                operands: [SME2Decode.group(gd, n, spec.dst), SME2Decode.group(gn, n, spec.src), src2],
                                reads: SME2Decode.groupMask(gn, n).union(src2Reads), writes: SME2Decode.groupMask(gd, n))
        }
    }

    @inline(__always)
    private static func convertDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic,
        operands: [Operand], reads: RegisterSet, writes: RegisterSet,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes, category: .sme,
            operands: operands, scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    private static func convertSpec(_ e: UInt32) -> CvtSpec? {
        switch e & 0xFFFF_FC63 {
        case 0xC131_E000: return CvtSpec(.fcvtzs, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC131_E020: return CvtSpec(.fcvtzu, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC132_E000: return CvtSpec(.scvtf, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC132_E020: return CvtSpec(.ucvtf, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC1B8_E000: return CvtSpec(.frintn, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC1B9_E000: return CvtSpec(.frintp, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC1BA_E000: return CvtSpec(.frintm, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        case 0xC1BC_E000: return CvtSpec(.frinta, shape: .same, count: 4, dst: .s, src: .s, sub: "")
        default: break
        }
        switch e & 0xFFFF_FC21 {
        case 0xC121_E000: return CvtSpec(.fcvtzs, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC121_E020: return CvtSpec(.fcvtzu, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC122_E000: return CvtSpec(.scvtf, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC122_E020: return CvtSpec(.ucvtf, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC1A8_E000: return CvtSpec(.frintn, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC1A9_E000: return CvtSpec(.frintp, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC1AA_E000: return CvtSpec(.frintm, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        case 0xC1AC_E000: return CvtSpec(.frinta, shape: .same, count: 2, dst: .s, src: .s, sub: "")
        default: break
        }
        switch e & 0xFFFF_FC60 {
        case 0xC133_E000: return CvtSpec(.sqcvt, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC133_E020: return CvtSpec(.uqcvt, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC133_E040: return CvtSpec(.sqcvtn, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC133_E060: return CvtSpec(.uqcvtn, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC134_E000: return CvtSpec(.fcvt, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC134_E020: return CvtSpec(.fcvtn, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC173_E000: return CvtSpec(.sqcvtu, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC173_E040: return CvtSpec(.sqcvtun, shape: .narrow, count: 4, dst: .b, src: .s, sub: "")
        case 0xC1B3_E000: return CvtSpec(.sqcvt, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        case 0xC1B3_E020: return CvtSpec(.uqcvt, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        case 0xC1B3_E040: return CvtSpec(.sqcvtn, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        case 0xC1B3_E060: return CvtSpec(.uqcvtn, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        case 0xC1F3_E000: return CvtSpec(.sqcvtu, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        case 0xC1F3_E040: return CvtSpec(.sqcvtun, shape: .narrow, count: 4, dst: .h, src: .d, sub: "")
        default: break
        }
        switch e & 0xFFE3_FC63 {
        case 0xC121_E400: return CvtSpec(.bfmul, shape: .fmul, count: 4, dst: .h, src: .h, sub: "zzw")
        case 0xC161_E400: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .h, src: .h, sub: "zzw")
        case 0xC1A1_E400: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .s, src: .s, sub: "zzw")
        case 0xC1E1_E400: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .d, src: .d, sub: "zzw")
        default: break
        }
        switch e & 0xFFFF_FC01 {
        case 0xC126_E000: return CvtSpec(.f1cvt, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC126_E001: return CvtSpec(.f1cvtl, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC166_E000: return CvtSpec(.bf1cvt, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC166_E001: return CvtSpec(.bf1cvtl, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC1A0_E000: return CvtSpec(.fcvt, shape: .widen, count: 2, dst: .s, src: .h, sub: "")
        case 0xC1A0_E001: return CvtSpec(.fcvtl, shape: .widen, count: 2, dst: .s, src: .h, sub: "")
        case 0xC1A6_E000: return CvtSpec(.f2cvt, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC1A6_E001: return CvtSpec(.f2cvtl, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC1E6_E000: return CvtSpec(.bf2cvt, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        case 0xC1E6_E001: return CvtSpec(.bf2cvtl, shape: .widen, count: 2, dst: .h, src: .b, sub: "")
        default: break
        }
        switch e & 0xFFFF_FC20 {
        case 0xC120_E000: return CvtSpec(.fcvt, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC120_E020: return CvtSpec(.fcvtn, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC123_E000: return CvtSpec(.sqcvt, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC123_E020: return CvtSpec(.uqcvt, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC124_E000: return CvtSpec(.fcvt, shape: .narrow, count: 2, dst: .b, src: .h, sub: "")
        case 0xC160_E000: return CvtSpec(.bfcvt, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC160_E020: return CvtSpec(.bfcvtn, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC163_E000: return CvtSpec(.sqcvtu, shape: .narrow, count: 2, dst: .h, src: .s, sub: "")
        case 0xC164_E000: return CvtSpec(.bfcvt, shape: .narrow, count: 2, dst: .b, src: .h, sub: "")
        default: break
        }
        switch e & 0xFFE1_FC63 {
        case 0xC121_E800: return CvtSpec(.bfmul, shape: .fmul, count: 4, dst: .h, src: .h, sub: "zzv")
        case 0xC161_E800: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .h, src: .h, sub: "zzv")
        case 0xC1A1_E800: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .s, src: .s, sub: "zzv")
        case 0xC1E1_E800: return CvtSpec(.fmul, shape: .fmul, count: 4, dst: .d, src: .d, sub: "zzv")
        default: break
        }
        switch e & 0xFFE1_FC21 {
        case 0xC120_E400: return CvtSpec(.bfmul, shape: .fmul, count: 2, dst: .h, src: .h, sub: "zzw")
        case 0xC120_E800: return CvtSpec(.bfmul, shape: .fmul, count: 2, dst: .h, src: .h, sub: "zzv")
        case 0xC160_E400: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .h, src: .h, sub: "zzw")
        case 0xC160_E800: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .h, src: .h, sub: "zzv")
        case 0xC1A0_E400: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .s, src: .s, sub: "zzw")
        case 0xC1A0_E800: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .s, src: .s, sub: "zzv")
        case 0xC1E0_E400: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .d, src: .d, sub: "zzw")
        case 0xC1E0_E800: return CvtSpec(.fmul, shape: .fmul, count: 2, dst: .d, src: .d, sub: "zzv")
        default: break
        }
        return nil
    }

    // MARK: - shared

    /// Element size from bits[23:22].
    @inline(__always)
    private static func sizeElement(_ e: UInt32) -> ScalarSize {
        switch (e >> 22) & 0x3 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }
}

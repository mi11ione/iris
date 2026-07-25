// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 vector-indexed memory decoders: 32-bit and 64-bit
// gather loads (scalar-base + vector index, and vector-base + immediate),
// scatter stores, the gather/scatter prefetch forms, the vector-base
// non-temporal gather/scatter (`gldnt`/`sstnt`), and the SVE2p1 quadword
// LD1Q/ST1Q. The gather regions (top bytes 0x84/0x85/0xC4/0xC5) also carry the
// co-located load-and-replicate (`sve_mem_ld_dup`), LDR fill, and gather
// prefetch, so the region sub-routers here classify those and delegate to the
// shared replicate / fill decoders.
//
// Operand structure only: gather/scatter addresses are recorded as (base,
// `Zm.<T>` index, extend, scale) via `ScalableMemoryOperand` — never computed
// (Piece 4). `flagEffect .none`, `readsStreamingMode` set; LDFF1 gather carries
// `.firstFaulting` + FFR; `gldnt`/`sstnt` carry `.nonTemporal`.

extension SVEPermuteMemoryDecode {
    // MARK: 32-bit gather region (0x84/0x85)

    /// Classify a 0x84/0x85 word (verified against llvm-mc): LDR fill, then by
    /// bit15 — the vector-base/replicate/prefetch column (bit15=1) vs the
    /// scalar-base gather / gather-prefetch column (bit15=0).
    @inline(__always)
    static func decode32bitGatherRegion(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // LDR (Z/P fill): bits[31:22]=1000010110 with bits[15:13]=010 (Z) or
        // 000 (P). (The same bits[31:22] with other markers are prfm_ss/gld.)
        if (e >> 22) & 0x3FF == 0b10_0001_0110 {
            let mk = (e >> 13) & 0b111
            if mk == 0b010 || mk == 0b000 { return decodeFillSpill(e, a, isStore: false) }
        }
        // prfm_si (contiguous prefetch, scalar+imm): bits[31:22]=1000010111,
        // bit15=0. `<prfop>, Pg, [Xn{, #imm6, mul vl}]`, msz=bits[14:13].
        if (e >> 22) & 0x3FF == 0b10_0001_0111, (e >> 15) & 1 == 0 {
            return decodePrefetchSI(e, a)
        }
        return decode32Gather(e, a)
    }

    /// Contiguous scalar+imm prefetch `<prfop>, Pg, [Xn{, #imm6, mul vl}]`.
    @inline(__always)
    static func decodePrefetchSI(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let msz = UInt8((e >> 13) & 0b11)
        let g = pg3(e), n = rn(e)
        let imm = signExtend6((e >> 16) & 0x3F)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr)
    }

    // MARK: 64-bit gather region (0xC4/0xC5)

    @inline(__always)
    static func decode64bitGatherRegion(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // The 64-bit region has no contiguous prefetch-si (that lives at 0x85);
        // every scalar-base word here is a gather.
        decode64Gather(e, a)
    }

    /// 0x84/0x85: bit15 splits scalar-base gather (0) from the vector-base /
    /// replicate / prefetch column (1).
    @inline(__always)
    static func decode32Gather(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 15) & 1 == 1 {
            if (e >> 22) & 1 == 1 { return decodeReplicate(e, a) } // LD1R
            if (e >> 21) & 1 == 1 { return decodeGatherVI(e, a, indexEl: .s) } // gld_vi
            switch (e >> 13) & 0b11 {
            // 32-bit gldnt: bits[14:13]=00 signed, 01 unsigned.
            case 0b00, 0b01: return decodeGatherNT(e, a, element: .s, signed: (e >> 13) & 0b11 == 0)
            case 0b10: return decodePrefetchSS(e, a) // contiguous prefetch [Xn, Xm]
            default: return decodePrefetchVI(e, a, indexEl: .s) // gather prefetch [Zn, #imm]
            }
        }
        // prfm_sv occupies the byte-scaled hole (bits[24:23]=00, bit21=1).
        if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .s) }
        return decodeGatherSV(e, a, indexEl: .s, packed: false)
    }

    /// 0xC4/0xC5: bit15 is the packed-64-bit-offset (`lsl`) bit for the
    /// scalar-base gather; the vector-base gldnt/LD1Q/prefetch forms are
    /// bit15=1 with bit22=0.
    @inline(__always)
    static func decode64Gather(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 15) & 1 == 1 {
            if (e >> 22) & 1 == 1 {
                // prfm_sv (scalar-base prefetch) occupies bits[24:23]=00, bit21=1.
                if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .d) }
                return decodeGatherSV(e, a, indexEl: .d, packed: true) // lsl gather
            }
            // bit21=1 → vector-base + immediate gather (`gld_vi`).
            if (e >> 21) & 1 == 1 { return decodeGatherVI(e, a, indexEl: .d) }
            // bit21=0, split by bits[14:13]: 00 gldnt-signed, 10 gldnt-unsigned,
            // 01 LD1Q (sz=00 only, else hole), 11 gather prefetch (prfm_vi).
            switch (e >> 13) & 0b11 {
            case 0b00: return decodeGatherNT(e, a, element: .d, signed: true)
            case 0b10: return decodeGatherNT(e, a, element: .d, signed: false)
            case 0b01: return (e >> 23) & 0b11 == 0 ? decodeLD1Q(e, a) : undefined(e, a)
            default: return decodePrefetchVI(e, a, indexEl: .d)
            }
        }
        if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .d) }
        return decodeGatherSV(e, a, indexEl: .d, packed: false)
    }

    // MARK: gather load forms

    /// Scalar-base + vector-index gather load `[Xn, Zm.<T>{, <extend>}{ #scale}]`.
    /// 32-bit uses uxtw/sxtw (bit22); 64-bit unpacked uses uxtw/sxtw (bit22),
    /// 64-bit packed (`packed`) uses `lsl`/none. Scaled by bit21.
    @inline(__always)
    static func decodeGatherSV(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize, packed: Bool) -> DecodedDraft {
        let opc = UInt8(((e >> 23) & 0b11) << 2 | ((e >> 13) & 0b11))
        guard let (mn, destEl, accessEl, ff) = gatherOpc(opc, wide: indexEl == .d) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let scaled = (e >> 21) & 1 == 1
        let extend: ExtendKind = if packed {
            scaled ? .lsl : .none // 64-bit packed offset
        } else {
            (e >> 22) & 1 == 1 ? .sxtw : .uxtw // 32-bit-unpacked offset
        }
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: extend,
            scaleShift: scaled ? elementScale(accessEl) : 0,
        )
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr)
        if ff { draft = markFirstFault(draft) }
        return draft
    }

    /// Vector-base + immediate gather load `[Zn.<T>{, #imm}]`.
    @inline(__always)
    static func decodeGatherVI(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize) -> DecodedDraft {
        let opc = UInt8(((e >> 23) & 0b11) << 2 | ((e >> 13) & 0b11))
        guard let (mn, destEl, accessEl, ff) = gatherOpc(opc, wide: indexEl == .d) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = Int32((e >> 16) & 0x1F) &* Int32(1 << elementScale(accessEl))
        let addr = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)), displacement: imm)
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr)
        if ff { draft = markFirstFault(draft) }
        return draft
    }

    /// LD1Q — SVE2p1 quadword gather: `{Zt.q}, Pg/z, [Zn.d, Xm]`.
    @inline(__always)
    static func decodeLD1Q(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: .d)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        return memLoadDraft(e, a, mn: .ld1q, zt: t, el: .q, g: g, addr: addr)
    }

    /// gldnt — vector-base non-temporal gather load `{Zt.<T>}, Pg/z, [Zn.<T>, Xm]`.
    /// The sign bit differs by width (32-bit: bit13; 64-bit: bit14), so the
    /// caller passes it; `.d` has no signed variant (that combo is a hole).
    @inline(__always)
    static func decodeGatherNT(_ e: UInt32, _ a: UInt64, element: ScalarSize, signed: Bool) -> DecodedDraft {
        guard let (mn, destEl) = gatherNTName(e, wide: element == .d, signed: signed) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        // Rm=31 (SP/XZR) renders `[Zn.<T>]` — no scalar index.
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: element)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        let draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr)
        return markNonTemporal(draft)
    }

    // MARK: gather prefetch

    /// Scalar-base + vector-index prefetch `<prfop>, Pg, [Xn, Zm.<T>{, ext #msz}]`.
    @inline(__always)
    static func decodePrefetchSV(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize) -> DecodedDraft {
        let msz = UInt8((e >> 13) & 0b11)
        let g = pg3(e), n = rn(e), m = rm(e)
        // 64-bit packed form (bit15=1) → lsl, but a byte access (msz=0) has no
        // shift so it renders bare `[Xn, Zm.d]` (extend .none); otherwise
        // uxtw/sxtw by bit22 (verified: c4200000 uxtw, c4600000 sxtw,
        // c460a000 lsl #1, c4608000 bare).
        let extend: ExtendKind = indexEl == .d && (e >> 15) & 1 == 1
            ? (msz > 0 ? .lsl : .none)
            : ((e >> 22) & 1 == 1 ? .sxtw : .uxtw)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: extend,
            scaleShift: msz,
        )
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr)
    }

    /// Vector-base + immediate prefetch `<prfop>, Pg, [Zn.<T>{, #imm}]`. The
    /// prfm_vi size is bits[24:23] (not [14:13]).
    @inline(__always)
    static func decodePrefetchVI(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize) -> DecodedDraft {
        let msz = UInt8((e >> 23) & 0b11)
        let g = pg3(e), n = rn(e)
        // The immediate is scaled by the prefetch element size (prfw → ×4).
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)),
            displacement: Int32((e >> 16) & 0x1F) &* Int32(1 << msz),
        )
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr)
    }

    /// Contiguous scalar+scalar prefetch `<prfop>, Pg, [Xn, Xm{, lsl #k}]`. The
    /// prfm_ss size is bits[24:23].
    @inline(__always)
    static func decodePrefetchSS(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) } // Rm=31 not a valid index
        let msz = UInt8((e >> 23) & 0b11)
        let g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: msz)
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr)
    }

    // MARK: scatter (from the store region)

    /// Scatter store, scalar-base + vector index `[Xn, Zm.<T>{, <extend>}{ #scale}]`.
    /// opc = bits[24:22] selects the (mnemonic, access element, index element);
    /// the extend (uxtw/sxtw/none) is passed from the mk column. Scaled by bit21.
    @inline(__always)
    static func decodeScatterSV(_ e: UInt32, _ a: UInt64, extend: ExtendKind) -> DecodedDraft {
        // At mk=101 (extend==.none) bit22=1 is the vector-base + immediate
        // scatter (`sst_vi`); opc packs as bits[24:23]:[21]. (At mk=100/110
        // bit22 is opc's low bit, so this only applies to the mk=101 column.)
        if extend == .none, (e >> 22) & 1 == 1 {
            let viOpc = UInt8(((e >> 23) & 0b11) << 1 | ((e >> 21) & 1))
            guard let (mn, el, indexEl) = scatterOpc(viOpc) else { return undefined(e, a) }
            let t = rd(e), g = pg3(e), n = rn(e)
            let imm = Int32((e >> 16) & 0x1F) &* Int32(1 << UInt8((e >> 23) & 0b11))
            let addr = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)), displacement: imm)
            return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr)
        }
        let opc = UInt8((e >> 22) & 0b111)
        guard let (mn, el, indexEl) = scatterOpc(opc) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let scaled = (e >> 21) & 1 == 1
        // Byte access (msz=bits[24:23]=00) has no scaled variant — scaled=1 there
        // is a hole llvm-mc rejects.
        if scaled, (e >> 23) & 0b11 == 0 { return undefined(e, a) }
        // `.none` from mk=101 becomes `.lsl` when scaled (64-bit packed offset).
        let effExtend: ExtendKind = extend == .none && scaled ? .lsl : extend
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: effExtend,
            // Scale = access (msz) log2 = bits[24:23], not the vector element.
            scaleShift: scaled ? UInt8((e >> 23) & 0b11) : 0,
        )
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr)
    }

    /// sstnt vector-base non-temporal scatter or ST1Q.
    @inline(__always)
    static func decodeScatterNTOrQuad(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bit21=1 → ST1Q (only when bits[24:22]=000; else a hole). bit21=0 →
        // the vector-base non-temporal scatter (`sstnt`).
        if (e >> 21) & 1 == 1 {
            return (e >> 22) & 0b111 == 0 ? decodeST1Q(e, a) : undefined(e, a)
        }
        return decodeScatterNTReg(e, a)
    }

    /// ST1Q — `{Zt.q}, Pg, [Zn.d, Xm]`.
    @inline(__always)
    static func decodeST1Q(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: .d)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        return memStoreDraft(e, a, mn: .st1q, zt: t, el: .q, g: g, addr: addr)
    }

    /// sstnt — vector-base non-temporal scatter `{Zt.<T>}, Pg, [Zn.<T>, Xm]`.
    @inline(__always)
    static func decodeScatterNTReg(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let opc = UInt8((e >> 22) & 0b111)
        guard let (mn, el) = scatterNTName(opc) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        // The vector-base index element is .d for 64-bit opc, .s for 32-bit.
        let indexEl: ScalarSize = opc & 1 == 0 ? .d : .s
        // Rm=31 renders `[Zn.<T>]` — no scalar index.
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        let draft = memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr)
        return markNonTemporal(draft)
    }

    // MARK: LD1R replicate (from the gather region)

    /// LD1R<x> — load and replicate a single element (`sve_mem_ld_dup`):
    /// `{Zt.<T>}, Pg/z, [Xn{, #imm}]`. (dtypeh, dtypel) select the mnemonic and
    /// element per the replicate table.
    @inline(__always)
    static func decodeReplicate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let dtypeh = UInt8((e >> 23) & 0b11)
        let dtypel = UInt8((e >> 13) & 0b11)
        let (mn, el, access) = replicateForm(dtypeh: dtypeh, dtypel: dtypel)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = Int32((e >> 16) & 0x3F) &* Int32(access)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm)
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr)
    }

    // MARK: helpers

    /// gather opc table: opc[3:0] = bits[24:23]:[14:13] → (mnemonic, dest
    /// element, **access** element, first-fault). The scale/immediate use the
    /// access size (bytes loaded), not the destination register size. `wide`
    /// selects the 64-bit opc extensions.
    @inline(__always)
    static func gatherOpc(_ opc: UInt8, wide: Bool) -> (Mnemonic, ScalarSize, ScalarSize, Bool)? {
        let dest: ScalarSize = wide ? .d : .s
        switch opc {
        case 0b0000: return (.ld1sb, dest, .b, false)
        case 0b0001: return (.ldff1sb, dest, .b, true)
        case 0b0010: return (.ld1b, dest, .b, false)
        case 0b0011: return (.ldff1b, dest, .b, true)
        case 0b0100: return (.ld1sh, dest, .h, false)
        case 0b0101: return (.ldff1sh, dest, .h, true)
        case 0b0110: return (.ld1h, dest, .h, false)
        case 0b0111: return (.ldff1h, dest, .h, true)
        case 0b1010: return (.ld1w, dest, .s, false)
        case 0b1011: return (.ldff1w, dest, .s, true)
        case 0b1000 where wide: return (.ld1sw, .d, .s, false)
        case 0b1001 where wide: return (.ldff1sw, .d, .s, true)
        case 0b1110 where wide: return (.ld1d, .d, .d, false)
        case 0b1111 where wide: return (.ldff1d, .d, .d, true)
        default: return nil
        }
    }

    /// gldnt name from the opc = bits[24:23]:[13] (element + sign).
    @inline(__always)
    static func gatherNTName(_ e: UInt32, wide: Bool, signed: Bool) -> (Mnemonic, ScalarSize)? {
        let dest: ScalarSize = wide ? .d : .s
        switch UInt8((e >> 23) & 0b11) {
        case 0b00: return (signed ? .ldnt1sb : .ldnt1b, dest)
        case 0b01: return (signed ? .ldnt1sh : .ldnt1h, dest)
        case 0b10:
            // A signed word only fits the 64-bit destination (no ldnt1sw.s).
            if signed { return wide ? (.ldnt1sw, dest) : nil }
            return (.ldnt1w, dest)
        default:
            // Doubleword: 64-bit unsigned only (no ldnt1sd, no 32-bit .s form).
            return wide && !signed ? (.ldnt1d, dest) : nil
        }
    }

    /// scatter opc table: opc[2:0] = bits[24:22] → (mnemonic, access element,
    /// index element).
    @inline(__always)
    static func scatterOpc(_ opc: UInt8) -> (Mnemonic, ScalarSize, ScalarSize)? {
        switch opc {
        case 0b000: (.st1b, .d, .d)
        case 0b001: (.st1b, .s, .s)
        case 0b010: (.st1h, .d, .d)
        case 0b011: (.st1h, .s, .s)
        case 0b100: (.st1w, .d, .d)
        case 0b101: (.st1w, .s, .s)
        case 0b110: (.st1d, .d, .d)
        default: nil
        }
    }

    /// sstnt name from the opc field.
    @inline(__always)
    static func scatterNTName(_ opc: UInt8) -> (Mnemonic, ScalarSize)? {
        // Even opc → 64-bit index (.d): b/h/w/d. Odd opc (bit22=1) → 32-bit
        // index (.s): b/h/w (no d — that combo is a hole).
        switch opc {
        case 0b000: (.stnt1b, .d)
        case 0b010: (.stnt1h, .d)
        case 0b100: (.stnt1w, .d)
        case 0b110: (.stnt1d, .d)
        case 0b001: (.stnt1b, .s)
        case 0b011: (.stnt1h, .s)
        case 0b101: (.stnt1w, .s)
        default: nil // 0b111 → hole
        }
    }

    /// PRF msz → mnemonic.
    @inline(__always)
    static func prefetchName(_ msz: UInt8) -> Mnemonic {
        switch msz {
        case 0b00: .prfb
        case 0b01: .prfh
        case 0b10: .prfw
        default: .prfd
        }
    }

    /// The replicate (LD1R*) (dtypeh, dtypel) → (mnemonic, element, access-size
    /// bytes for the immediate scale) table (`sve_mem_ld_dup`).
    @inline(__always)
    static func replicateForm(dtypeh: UInt8, dtypel: UInt8) -> (Mnemonic, ScalarSize, Int32) {
        switch (dtypeh, dtypel) {
        case (0b00, 0b00): (.ld1rb, .b, 1)
        case (0b00, 0b01): (.ld1rb, .h, 1)
        case (0b00, 0b10): (.ld1rb, .s, 1)
        case (0b00, 0b11): (.ld1rb, .d, 1)
        case (0b01, 0b00): (.ld1rsw, .d, 4)
        case (0b01, 0b01): (.ld1rh, .h, 2)
        case (0b01, 0b10): (.ld1rh, .s, 2)
        case (0b01, 0b11): (.ld1rh, .d, 2)
        case (0b10, 0b00): (.ld1rsh, .d, 2)
        case (0b10, 0b01): (.ld1rsh, .s, 2)
        case (0b10, 0b10): (.ld1rw, .s, 4)
        case (0b10, 0b11): (.ld1rw, .d, 4)
        case (0b11, 0b00): (.ld1rsb, .d, 1)
        case (0b11, 0b01): (.ld1rsb, .s, 1)
        case (0b11, 0b10): (.ld1rsb, .h, 1)
        default: (.ld1rd, .d, 8)
        }
    }
}

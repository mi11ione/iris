// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 scalar-base memory decoders and the memory
// region router. Covers contiguous LD1/ST1 (scalar+imm and scalar+scalar),
// LDNF1/LDFF1, LDNT1/STNT1, LD1R*/LD1RQ/LD1RO (load-and-replicate), the
// structured LD2-4/ST2-4 (+ SVE2p1 Q forms), and LDR/STR register fill/spill.
// `decodeMemory` (the memory region entry) routes every bit31=1 word by top-
// byte group and the class marker bits[15:13] to the right family — the
// vector-indexed gather/scatter/prefetch forms live in SVEGatherScatterDecode.
//
// Memory-access classification: `.load`/`.store` base kind, with
// `.firstFaulting`/`.nonFaulting` + FFR read/write for LDFF1/LDNF1 and
// `.nonTemporal` for LDNT1/STNT1. `flagEffect .none`, `readsStreamingMode`
// set, loads are full-writes (not partialWrite). Addresses are recorded as
// operand structure only — never computed.

extension SVEPermuteMemoryDecode {
    // MARK: memory region router

    /// Route a memory-region word (bit31=1) by top-byte group (bits[31:29])
    /// and the class marker.
    @inline(__always)
    static func decodeMemory(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 29) & 0b111 {
        case 0b100: decode32bitGatherRegion(e, a, &sink) // 0x84/0x85
        case 0b101: decodeContiguousLoadRegion(e, a, &sink) // 0xA4/0xA5
        case 0b110: decode64bitGatherRegion(e, a, &sink) // 0xC4/0xC5
        default: decodeStoreRegion(e, a, &sink) // 0xE4/0xE5
        }
    }

    // MARK: contiguous load region (0xA4/0xA5)

    /// The contiguous / structured / replicate / fault load region. mk =
    /// bits[15:13]: 101 cld_si (LD1/LDNF1 imm), 010/011 cld_ss (LD1/LDFF1 reg),
    /// 111 eld_si or cldnt_si (structured imm / LDNT1 imm), 110 eld_ss / cldnt_ss,
    /// 000/001 ld1rq/ld1ro (replicate).
    @inline(__always)
    static func decodeContiguousLoadRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mk = (e >> 13) & 0b111
        switch mk {
        case 0b101: return decodeContiguousLoadSI(e, a, &sink)
        case 0b010: return decodeContiguousLoadSS(e, a, firstFault: false, &sink)
        case 0b011: return decodeContiguousLoadSS(e, a, firstFault: true, &sink)
        case 0b111:
            // bits[22:20]=000 → LDNT1 imm (cldnt_si); else structured (eld_si).
            return (e >> 20) & 0b111 == 0 ? decodeContiguousNTImm(e, a, isStore: false, &sink)
                : decodeStructuredImm(e, a, &sink)
        case 0b110:
            // bits[22:21]=00 → LDNT1 reg (cldnt_ss); else structured (eld_ss).
            return (e >> 21) & 0b11 == 0 ? decodeContiguousNTReg(e, a, isStore: false, &sink)
                : decodeStructuredReg(e, a, &sink)
        case 0b001: return decodeReplicateQuad(e, a, &sink)
        case 0b000: return decodeReplicateQuadReg(e, a, &sink)
        // mk is 3-bit and every value is handled above; the final arm (mk=100)
        // doubles as the default (ld1{w,d}.q + ld2q-4q reg-offset).
        default: return decode128bLoad(e, a, &sink)
        }
    }

    /// SVE2p1 128-bit loads at mk=100: bits[22:20]=000 → contiguous quadword
    /// `ld1w`/`ld1d` `{Zt.q}, Pg/z, [Xn, Xm, lsl #k]` (bits[24:23]=10→w, 11→d);
    /// else the register-offset quadword structured `ld2q`-`ld4q`
    /// `{Zt.q,...}, Pg/z, [Xn, Xm, lsl #4]` (count = bits[24:23]: 01/10/11).
    @inline(__always)
    static func decode128bLoad(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // bits[22:21]: 00 → 128b contiguous ld1{w,d}.q ss; 01 → quadword
        // structured ld2q-4q reg-offset; else hole. (bit20 is Rm's top bit.)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        guard m != 31 else { return undefined(e, a) } // Rm=31 not a valid index
        switch (e >> 21) & 0b11 {
        case 0b00:
            let mn: Mnemonic
            switch (e >> 23) & 0b11 {
            case 0b10: mn = .ld1w
            case 0b11: mn = .ld1d
            default: return undefined(e, a)
            }
            let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: 2 + UInt8((e >> 23) & 1))
            return memLoadDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, &sink)
        case 0b01:
            // Rm=31 already rejected by the shared guard above.
            let count: UInt8
            switch (e >> 23) & 0b11 {
            case 0b01: count = 2
            case 0b10: count = 3
            case 0b11: count = 4
            default: return undefined(e, a)
            }
            let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: 4)
            let mn = structuredName(count: count, element: .q, isStore: false)
            return memLoadDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, groupCount: count, &sink)
        default:
            return undefined(e, a)
        }
    }

    /// LD1<dtype> / LDNF1<dtype> `{Zt.<T>}, Pg/z, [Xn{, #imm4, mul vl}]`.
    /// dtype=bits[24:21], nf=bit20, imm4=bits[19:16] (signed, mul vl).
    @inline(__always)
    static func decodeContiguousLoadSI(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dtype = UInt8((e >> 21) & 0xF)
        let (mn, el) = loadDtype(dtype, nonFault: (e >> 20) & 1 == 1)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        if (e >> 20) & 1 == 1 { draft = markNonFault(draft) }
        return draft
    }

    /// LD1<dtype> / LDFF1<dtype> `{Zt.<T>}, Pg/z, [Xn, Xm{, lsl #k}]`.
    /// dtype=bits[24:21], Rm=bits[20:16].
    @inline(__always)
    static func decodeContiguousLoadSS(_ e: UInt32, _ a: UInt64, firstFault: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let m = rm(e)
        // Rm=31: plain LD1 rejects it (no `[x, xzr]`), but LDFF1 with Rm=31 is
        // the valid first-fault `[Xn]` form (no index).
        if m == 31, !firstFault { return undefined(e, a) }
        let dtype = UInt8((e >> 21) & 0xF)
        let (baseMn, el) = loadDtype(dtype, nonFault: false)
        let mn = firstFault ? firstFaultName(baseMn) : baseMn
        let t = rd(e), g = pg3(e), n = rn(e)
        // The register-offset shift is the access (loaded-element) log2 size, not
        // the destination container — `ld1b {z.h}, [x, x]` has no `lsl`.
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: m == 31 ? nil : .x(m), scaleShift: loadAccessScale(dtype),
        )
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        if firstFault { draft = markFirstFault(draft) }
        return draft
    }

    /// LDNT1<msz> `{Zt.<T>}, Pg/z, [Xn{, #imm4, mul vl}]` (contiguous
    /// non-temporal, imm). msz=bits[24:23].
    @inline(__always)
    static func decodeContiguousNTImm(_ e: UInt32, _ a: UInt64, isStore: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let msz = UInt8((e >> 23) & 0b11)
        let el = esize(msz)
        let mn = ntName(msz: msz, isStore: isStore)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        let draft = isStore
            ? memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
            : memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        return markNonTemporal(draft)
    }

    /// LDNT1<msz>/STNT1<msz> `{Zt.<T>}, Pg/z, [Xn, Xm]` (contiguous
    /// non-temporal, register offset).
    @inline(__always)
    static func decodeContiguousNTReg(_ e: UInt32, _ a: UInt64, isStore: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        let msz = UInt8((e >> 23) & 0b11)
        let el = esize(msz)
        let mn = ntName(msz: msz, isStore: isStore)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: elementScale(el),
        )
        let draft = isStore
            ? memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
            : memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        return markNonTemporal(draft)
    }

    /// LD2-4<T> / LD2Q-4Q `{Zt1.<T>...Ztn.<T>}, Pg/z, [Xn{, #imm, mul vl}]`.
    /// sz=bits[24:23], nregs=bits[22:20] (010/100/110 → ×2/×3/×4; 001 → Q).
    /// Load-only — the store region has its own est_si decoder.
    @inline(__always)
    static func decodeStructuredImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (count, el, mn) = structuredForm(e) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// Structured register-offset load form `[Xn, Xm{, lsl #k}]`. nregs =
    /// bits[22:21] (the caller routes bits[22:21]==0 to LDNT1, so nregs ≥ 1).
    @inline(__always)
    static func decodeStructuredReg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        let count = UInt8((e >> 21) & 0b11) + 1
        let el = esize(UInt8((e >> 23) & 0b11))
        let mn = structuredName(count: count, element: el, isStore: false)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: elementScale(el),
        )
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// SVE2p1 128-bit contiguous `ld1w`/`ld1d` `{Zt.q}, Pg/z, [Xn{, #imm, mul vl}]`
    /// (imm form, mk=001 bits[22:20]=001). bits[24:23]=10→w, 11→d.
    @inline(__always)
    static func decode128bContiguousImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mn: Mnemonic
        switch (e >> 23) & 0b11 {
        case 0b10: mn = .ld1w
        case 0b11: mn = .ld1d
        default: return undefined(e, a)
        }
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memLoadDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, &sink)
    }

    /// LD1RQ<sz> / LD1RO<sz> `{Zt.<T>}, Pg/z, [Xn{, #imm}]` (quad/oct replicate,
    /// imm form). bits[22:20]=000 → LD1RQ, 010 → LD1RO (F64MM).
    @inline(__always)
    static func decodeReplicateQuad(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // bits[22:20]: 000 → LD1RQ, 010 → LD1RO (F64MM); every other value is a
        // hole. (LD1RO is byte-invalid: sz=00 renders no ld1rob at 010 — llvm
        // rejects it, so the sweep gates a byte octoword; guarded by size below.)
        let marker = (e >> 20) & 0b111
        // bits[22:20]=001 → SVE2p1 128-bit contiguous ld1{w,d}.q imm form.
        if marker == 0b001 { return decode128bContiguousImm(e, a, &sink) }
        guard marker == 0b000 || marker == 0b010 else { return undefined(e, a) }
        let sz = UInt8((e >> 23) & 0b11)
        let el = esize(sz)
        let isOcto = marker == 0b010
        let mn = isOcto ? octoReplicateName(sz) : quadReplicateName(sz)
        let t = rd(e), g = pg3(e), n = rn(e)
        let scale: Int32 = isOcto ? 32 : 16
        let imm = signExtend4((e >> 16) & 0xF) &* scale
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm)
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    /// LD1RQ<sz>/LD1RO<sz> register-offset `{Zt.<T>}, Pg/z, [Xn, Xm{, lsl}]`.
    @inline(__always)
    static func decodeReplicateQuadReg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        // Register-offset form: bits[22:21]=00 → LD1RQ, 01 → LD1RO (F64MM).
        let marker = (e >> 21) & 0b11
        guard marker == 0b00 || marker == 0b01 else { return undefined(e, a) }
        let sz = UInt8((e >> 23) & 0b11)
        let el = esize(sz)
        let isOcto = marker == 0b01
        let mn = isOcto ? octoReplicateName(sz) : quadReplicateName(sz)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: elementScale(el),
        )
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    // MARK: store region (0xE4/0xE5)

    /// The contiguous / structured / scatter / non-temporal store region and
    /// STR spill (0xE4/0xE5). Routed by mk = bits[15:13] (verified against
    /// llvm-mc).
    @inline(__always)
    static func decodeStoreRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // STR spill (bits[31:22]=1110010110, mk=010 Z / 000 P).
        if (e >> 22) & 0x3FF == 0b11_1001_0110 {
            let mk0 = (e >> 13) & 0b111
            if mk0 == 0b010 || mk0 == 0b000 { return decodeFillSpill(e, a, isStore: true, &sink) }
        }
        switch (e >> 13) & 0b111 {
        case 0b010: return decodeContiguousStoreSS(e, a, &sink) // ST1 [Xn, Xm] (cst_ss)
        case 0b011: // STNT1 [Xn, Xm] (bits[22:21]=00) or structured [Xn, Xm].
            return (e >> 21) & 0b11 == 0 ? decodeContiguousNTReg(e, a, isStore: true, &sink)
                : decodeStoreStructuredReg(e, a, &sink)
        case 0b111: // ST1 [Xn, #imm] / STNT1 imm / structured imm.
            return decodeStoreImmOrStructured(e, a, &sink)
        case 0b100: return decodeScatterSV(e, a, extend: .uxtw, &sink)
        case 0b101: return decodeScatterSV(e, a, extend: .none, &sink) // 64-bit unscaled / lsl
        case 0b110: return decodeScatterSV(e, a, extend: .sxtw, &sink)
        case 0b001: return decodeScatterNTOrQuad(e, a, &sink) // sstnt / ST1Q
        default: return decodeStore128Structured(e, a, &sink) // mk=000: ST2Q-4Q (128b est)
        }
    }

    /// ST1<msz> `{Zt.<T>}, Pg, [Xn{, #imm4, mul vl}]` (cst_si), STNT1 imm, or
    /// structured est_si. bit20=0 → cst_si single; bit20=1 → STNT1 (nregs=00) /
    /// structured (nregs=bits[22:21]).
    @inline(__always)
    static func decodeStoreImmOrStructured(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 20) & 1 == 0 {
            // cst_si single vector: msz=bits[24:23], esz=bits[22:21]. The
            // container element is esz, except the _q forms (st1w_q: msz=10
            // esz=00; st1d_q: msz=11 esz=10) whose container is `.q`.
            let msz = UInt8((e >> 23) & 0b11), esz = UInt8((e >> 21) & 0b11)
            guard esz >= msz || (msz == 0b10 && esz == 0) || (msz == 0b11 && esz == 0b10) else { return undefined(e, a) }
            let el: ScalarSize = (msz == 0b10 && esz == 0) || (msz == 0b11 && esz == 0b10) ? .q : esize(esz)
            let t = rd(e), g = pg3(e), n = rn(e)
            let imm = signExtend4((e >> 16) & 0xF)
            let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
            return memStoreDraft(e, a, mn: storeMsz(msz), zt: t, el: el, g: g, addr: addr, &sink)
        }
        if (e >> 21) & 0b11 == 0 { return decodeContiguousNTImm(e, a, isStore: true, &sink) }
        return decodeStoreStructuredImm(e, a, &sink)
    }

    /// Store structured `[Xn{, #imm, mul vl}]` (est_si). nregs=bits[22:21],
    /// count=nregs+1 (01→2, 10→3, 11→4); element from sz=bits[24:23].
    @inline(__always)
    static func decodeStoreStructuredImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // nregs = bits[22:21] != 0 (the caller routes bits[22:21]==0 to STNT1).
        let count = UInt8((e >> 21) & 0b11) + 1
        let el = esize(UInt8((e >> 23) & 0b11))
        let mn = structuredName(count: count, element: el, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// Store structured `[Xn, Xm{, lsl}]` (est_ss). nregs = bits[22:21] != 0
    /// (the caller routes bits[22:21]==0 to STNT1).
    @inline(__always)
    static func decodeStoreStructuredReg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) } // Rm=31 invalid index
        let count = UInt8((e >> 21) & 0b11) + 1
        let el = esize(UInt8((e >> 23) & 0b11))
        let mn = structuredName(count: count, element: el, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: elementScale(el))
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// 128-bit structured store ST2Q-4Q (`sve_mem_128b_est_si`/`_ss`) at mk=000
    /// (0xE4 only, bit24=0). nregs = bits[23:22] (01/10/11 → 2/3/4). bit21=0 →
    /// immediate form `[Xn{, #imm, mul vl}]`; bit21=1 → register-offset form
    /// `[Xn, Xm, lsl #4]`.
    @inline(__always)
    static func decodeStore128Structured(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 24) & 1 == 0 else { return undefined(e, a) } // 0xE4 only
        let nregs = (e >> 22) & 0b11
        guard nregs != 0 else { return undefined(e, a) }
        let count = UInt8(nregs) + 1
        let mn = structuredName(count: count, element: .q, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e)
        if (e >> 21) & 1 == 1 {
            // Register-offset form (bit20 is Rm's top bit).
            guard rm(e) != 31 else { return undefined(e, a) }
            let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(rm(e)), scaleShift: 4)
            return memStoreDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, groupCount: count, &sink)
        }
        // Immediate form requires bit20=0 (bit21=0,bit20=1 is a hole).
        guard (e >> 20) & 1 == 0 else { return undefined(e, a) }
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memStoreDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, groupCount: count, &sink)
    }

    /// ST1<dtype> `{Zt.<T>}, Pg, [Xn, Xm{, lsl}]` (cst_ss). dtype=bits[24:21]
    /// selects (mnemonic, element) — includes the st1w_q/st1d_q forms.
    @inline(__always)
    static func decodeContiguousStoreSS(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // Rm=31 (SP/XZR) is not a valid index for the register-offset stores.
        guard rm(e) != 31 else { return undefined(e, a) }
        let dtype = UInt8((e >> 21) & 0xF)
        guard let (mn, el) = storeDtype(dtype) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        // The register-offset shift is the access (msz) log2, not the element.
        let msz = UInt8((e >> 23) & 0b11)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: msz,
        )
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    /// LDR/STR register fill/spill decode — dispatched from the 0x85 (LDR) and
    /// 0xE5 (STR) marker. imm9 = bits[21:16]:[12:10] (signed, mul vl); bits
    /// [15:13]=010 → Z register, 000 → P register.
    @inline(__always)
    static func decodeFillSpill(_ e: UInt32, _ a: UInt64, isStore: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let isPred = (e >> 13) & 0b111 == 0b000
        // The P-register form has a 4-bit Pt at bits[3:0]; bit4 is fixed 0.
        if isPred, (e >> 4) & 1 != 0 { return undefined(e, a) }
        let t = rd(e), n = rn(e)
        let imm9 = signExtend9(((e >> 16) & 0x3F) << 3 | ((e >> 10) & 0x7))
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm9, mulVL: true)
        let data: Operand = isPred
            ? .scalablePredicate(ScalablePredicateRef(registerIndex: t & 0xF, role: .governing))
            : vecPlain(t)
        // The base `Xn` is always read (address). LDR writes the filled Z/P
        // register; STR reads the spilled Z/P register (data) and writes
        // nothing. The Z register rides the GPR/SIMD mask (bit 32+t); the P
        // register rides the scalable set.
        let base = gprMask(n)
        let semReads: RegisterSet
        let semWrites: RegisterSet
        let sReads: ScalableRegisterSet
        let sWrites: ScalableRegisterSet
        if isStore {
            semReads = isPred ? base : base.union(vecMask(t))
            semWrites = .empty
            sReads = isPred ? predRead(t & 0xF) : .empty
            sWrites = .empty
        } else {
            semReads = base
            semWrites = isPred ? .empty : vecMask(t)
            sReads = .empty
            sWrites = isPred ? predRead(t & 0xF) : .empty
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: isStore ? .str : .ldr,
            semanticReads: semReads,
            semanticWrites: semWrites,
            memoryAccess: isStore ? .store : .load, category: .sve,
            operandCount: sink.emit(data, .scalableMemory(addr)),
            scalableReads: sReads, scalableWrites: sWrites,
            scalableEffect: .readsStreamingMode,
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPermuteMemoryDecode {
    /// Classify a 0x84/0x85 word (verified against llvm-mc).
    @inline(__always)
    static func decode32bitGatherRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 22) & 0x3FF == 0b10_0001_0110 {
            let mk = (e >> 13) & 0b111
            if mk == 0b010 || mk == 0b000 { return decodeFillSpill(e, a, isStore: false, &sink) }
        }
        if (e >> 22) & 0x3FF == 0b10_0001_0111, (e >> 15) & 1 == 0 {
            return decodePrefetchSI(e, a, &sink)
        }
        return decode32Gather(e, a, &sink)
    }

    /// Contiguous scalar+imm prefetch `<prfop>, Pg, [Xn{, #imm6, mul vl}]`.
    @inline(__always)
    static func decodePrefetchSI(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let msz = UInt8((e >> 13) & 0b11)
        let g = pg3(e), n = rn(e)
        let imm = signExtend6((e >> 16) & 0x3F)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr, &sink)
    }

    @inline(__always)
    static func decode64bitGatherRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        decode64Gather(e, a, &sink)
    }

    /// 0x84/0x85: bit15 splits scalar-base gather (0) from the vector-base /
    /// replicate / prefetch column (1).
    @inline(__always)
    static func decode32Gather(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 15) & 1 == 1 {
            if (e >> 22) & 1 == 1 { return decodeReplicate(e, a, &sink) }
            if (e >> 21) & 1 == 1 { return decodeGatherVI(e, a, indexEl: .s, &sink) }
            switch (e >> 13) & 0b11 {
            case 0b00, 0b01: return decodeGatherNT(e, a, element: .s, signed: (e >> 13) & 0b11 == 0, &sink)
            case 0b10: return decodePrefetchSS(e, a, &sink)
            default: return decodePrefetchVI(e, a, indexEl: .s, &sink)
            }
        }
        if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .s, &sink) }
        return decodeGatherSV(e, a, indexEl: .s, packed: false, &sink)
    }

    /// 0xC4/0xC5: bit15 is the packed-64-bit-offset (`lsl`) bit for the
    /// scalar-base gather; the vector-base gldnt/LD1Q/prefetch forms are
    /// bit15=1 with bit22=0.
    @inline(__always)
    static func decode64Gather(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 15) & 1 == 1 {
            if (e >> 22) & 1 == 1 {
                if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .d, &sink) }
                return decodeGatherSV(e, a, indexEl: .d, packed: true, &sink)
            }
            if (e >> 21) & 1 == 1 { return decodeGatherVI(e, a, indexEl: .d, &sink) }
            switch (e >> 13) & 0b11 {
            case 0b00: return decodeGatherNT(e, a, element: .d, signed: true, &sink)
            case 0b10: return decodeGatherNT(e, a, element: .d, signed: false, &sink)
            case 0b01: return (e >> 23) & 0b11 == 0 ? decodeLD1Q(e, a, &sink) : undefined(e, a)
            default: return decodePrefetchVI(e, a, indexEl: .d, &sink)
            }
        }
        if (e >> 23) & 0b11 == 0, (e >> 21) & 1 == 1 { return decodePrefetchSV(e, a, indexEl: .d, &sink) }
        return decodeGatherSV(e, a, indexEl: .d, packed: false, &sink)
    }

    /// Scalar-base + vector-index gather load `[Xn, Zm.<T>{, <extend>}{
    /// #scale}]`.
    @inline(__always)
    static func decodeGatherSV(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize, packed: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let opcBits: UInt32 = ((e >> 23) & 0b11) << 2 | ((e >> 13) & 0b11)
        let opc = UInt8(opcBits)
        guard let (mn, destEl, accessEl, ff) = gatherOpc(opc, wide: indexEl == .d) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let scaled = (e >> 21) & 1 == 1
        let extend: ExtendKind = if packed {
            scaled ? .lsl : .none
        } else {
            (e >> 22) & 1 == 1 ? .sxtw : .uxtw
        }
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: extend,
            scaleShift: scaled ? elementScale(accessEl) : 0,
        )
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr, &sink)
        if ff { draft = markFirstFault(draft) }
        return draft
    }

    /// Vector-base + immediate gather load `[Zn.<T>{, #imm}]`.
    @inline(__always)
    static func decodeGatherVI(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let opcBits: UInt32 = ((e >> 23) & 0b11) << 2 | ((e >> 13) & 0b11)
        let opc = UInt8(opcBits)
        guard let (mn, destEl, accessEl, ff) = gatherOpc(opc, wide: indexEl == .d) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = Int32((e >> 16) & 0x1F) &* Int32(1 << elementScale(accessEl))
        let addr = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)), displacement: imm)
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr, &sink)
        if ff { draft = markFirstFault(draft) }
        return draft
    }

    /// LD1Q — SVE2p1 quadword gather: `{Zt.q}, Pg/z, [Zn.d, Xm]`.
    @inline(__always)
    static func decodeLD1Q(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: .d)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        return memLoadDraft(e, a, mn: .ld1q, zt: t, el: .q, g: g, addr: addr, &sink)
    }

    /// gldnt — vector-base non-temporal gather load `{Zt.<T>}, Pg/z, [Zn.<T>,
    /// Xm]`. The sign bit differs by width (32-bit: bit13; 64-bit: bit14), so
    /// the caller passes it; `.d` has no signed variant (that combo is a
    /// hole).
    @inline(__always)
    static func decodeGatherNT(_ e: UInt32, _ a: UInt64, element: ScalarSize, signed: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (mn, destEl) = gatherNTName(e, wide: element == .d, signed: signed) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: element)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        let draft = memLoadDraft(e, a, mn: mn, zt: t, el: destEl, g: g, addr: addr, &sink)
        return markNonTemporal(draft)
    }

    /// Scalar-base + vector-index prefetch `<prfop>, Pg, [Xn, Zm.<T>{, ext
    /// #msz}]`.
    @inline(__always)
    static func decodePrefetchSV(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let msz = UInt8((e >> 13) & 0b11)
        let g = pg3(e), n = rn(e), m = rm(e)
        let extend: ExtendKind = indexEl == .d && (e >> 15) & 1 == 1
            ? (msz > 0 ? .lsl : .none)
            : ((e >> 22) & 1 == 1 ? .sxtw : .uxtw)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: extend,
            scaleShift: msz,
        )
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr, &sink)
    }

    /// Vector-base + immediate prefetch `<prfop>, Pg, [Zn.<T>{, #imm}]`.
    @inline(__always)
    static func decodePrefetchVI(_ e: UInt32, _ a: UInt64, indexEl: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let msz = UInt8((e >> 23) & 0b11)
        let g = pg3(e), n = rn(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)),
            displacement: Int32((e >> 16) & 0x1F) &* Int32(1 << msz),
        )
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr, &sink)
    }

    /// Contiguous scalar+scalar prefetch `<prfop>, Pg, [Xn, Xm{, lsl #k}]`.
    @inline(__always)
    static func decodePrefetchSS(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        let msz = UInt8((e >> 23) & 0b11)
        let g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: msz)
        return memPrefetchDraft(e, a, mn: prefetchName(msz), g: g, addr: addr, &sink)
    }

    /// Scatter store, scalar-base + vector index `[Xn, Zm.<T>{, <extend>}{
    /// #scale}]`.
    @inline(__always)
    static func decodeScatterSV(_ e: UInt32, _ a: UInt64, extend: ExtendKind, _ sink: inout OperandSink) -> DecodedDraft {
        if extend == .none, (e >> 22) & 1 == 1 {
            let viOpcBits: UInt32 = ((e >> 23) & 0b11) << 1 | ((e >> 21) & 1)
            let viOpc = UInt8(viOpcBits)
            guard let (mn, el, indexEl) = scatterOpc(viOpc) else { return undefined(e, a) }
            let t = rd(e), g = pg3(e), n = rn(e)
            let imm = Int32((e >> 16) & 0x1F) &* Int32(1 << UInt8((e >> 23) & 0b11))
            let addr = ScalableMemoryOperand(base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)), displacement: imm)
            return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        }
        let opc = UInt8((e >> 22) & 0b111)
        guard let (mn, el, indexEl) = scatterOpc(opc) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let scaled = (e >> 21) & 1 == 1
        if scaled, (e >> 23) & 0b11 == 0 { return undefined(e, a) }
        let effExtend: ExtendKind = extend == .none && scaled ? .lsl : extend
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)),
            index: ScalableVectorRef(registerIndex: m, element: indexEl),
            indexExtend: effExtend,
            scaleShift: scaled ? UInt8((e >> 23) & 0b11) : 0,
        )
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    /// sstnt vector-base non-temporal scatter or ST1Q.
    @inline(__always)
    static func decodeScatterNTOrQuad(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 1 {
            return (e >> 22) & 0b111 == 0 ? decodeST1Q(e, a, &sink) : undefined(e, a)
        }
        return decodeScatterNTReg(e, a, &sink)
    }

    /// ST1Q — `{Zt.q}, Pg, [Zn.d, Xm]`.
    @inline(__always)
    static func decodeST1Q(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: .d)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        return memStoreDraft(e, a, mn: .st1q, zt: t, el: .q, g: g, addr: addr, &sink)
    }

    /// sstnt — vector-base non-temporal scatter `{Zt.<T>}, Pg, [Zn.<T>, Xm]`.
    @inline(__always)
    static func decodeScatterNTReg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opc = UInt8((e >> 22) & 0b111)
        guard let (mn, el) = scatterNTName(opc) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let indexEl: ScalarSize = opc & 1 == 0 ? .d : .s
        let addr = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: indexEl)),
            scalarIndex: m == 31 ? nil : .x(m),
        )
        let draft = memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        return markNonTemporal(draft)
    }

    /// LD1R<x> — load and replicate a single element (`sve_mem_ld_dup`):
    /// `{Zt.<T>}, Pg/z, [Xn{, #imm}]`. (dtypeh, dtypel) select the mnemonic
    /// and element per the replicate table.
    @inline(__always)
    static func decodeReplicate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dtypeh = UInt8((e >> 23) & 0b11)
        let dtypel = UInt8((e >> 13) & 0b11)
        let (mn, el, access) = replicateForm(dtypeh: dtypeh, dtypel: dtypel)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = Int32((e >> 16) & 0x3F) &* Int32(access)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm)
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    /// Gather opc table.
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
            if signed { return wide ? (.ldnt1sw, dest) : nil }
            return (.ldnt1w, dest)
        default:
            return wide && !signed ? (.ldnt1d, dest) : nil
        }
    }

    /// scatter opc table.
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
        switch opc {
        case 0b000: (.stnt1b, .d)
        case 0b010: (.stnt1h, .d)
        case 0b100: (.stnt1w, .d)
        case 0b110: (.stnt1d, .d)
        case 0b001: (.stnt1b, .s)
        case 0b011: (.stnt1h, .s)
        case 0b101: (.stnt1w, .s)
        default: nil
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

    /// The replicate (LD1R*) (dtypeh, dtypel) → (mnemonic, element,
    /// access-size bytes for the immediate scale) table (`sve_mem_ld_dup`).
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

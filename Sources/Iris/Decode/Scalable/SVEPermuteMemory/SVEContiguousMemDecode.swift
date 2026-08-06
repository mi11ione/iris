// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPermuteMemoryDecode {
    /// Route a memory-region word (bit31=1) by top-byte group (bits[31:29])
    /// and the class marker.
    @inline(__always)
    static func decodeMemory(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 29) & 0b111 {
        case 0b100: decode32bitGatherRegion(e, a, &sink)
        case 0b101: decodeContiguousLoadRegion(e, a, &sink)
        case 0b110: decode64bitGatherRegion(e, a, &sink)
        default: decodeStoreRegion(e, a, &sink)
        }
    }

    /// The contiguous / structured / replicate / fault load region, by mk =
    /// bits[15:13].
    @inline(__always)
    static func decodeContiguousLoadRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mk = (e >> 13) & 0b111
        switch mk {
        case 0b101: return decodeContiguousLoadSI(e, a, &sink)
        case 0b010: return decodeContiguousLoadSS(e, a, firstFault: false, &sink)
        case 0b011: return decodeContiguousLoadSS(e, a, firstFault: true, &sink)
        case 0b111:
            return (e >> 20) & 0b111 == 0 ? decodeContiguousNTImm(e, a, isStore: false, &sink)
                : decodeStructuredImm(e, a, &sink)
        case 0b110:
            return (e >> 21) & 0b11 == 0 ? decodeContiguousNTReg(e, a, isStore: false, &sink)
                : decodeStructuredReg(e, a, &sink)
        case 0b001: return decodeReplicateQuad(e, a, &sink)
        case 0b000: return decodeReplicateQuadReg(e, a, &sink)
        default: return decode128bLoad(e, a, &sink)
        }
    }

    /// SVE2p1 128-bit loads at mk=100.
    @inline(__always)
    static func decode128bLoad(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        guard m != 31 else { return undefined(e, a) }
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
    @inline(__always)
    static func decodeContiguousLoadSS(_ e: UInt32, _ a: UInt64, firstFault: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let m = rm(e)
        if m == 31, !firstFault { return undefined(e, a) }
        let dtype = UInt8((e >> 21) & 0xF)
        let (baseMn, el) = loadDtype(dtype, nonFault: false)
        let mn = firstFault ? firstFaultName(baseMn) : baseMn
        let t = rd(e), g = pg3(e), n = rn(e)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: m == 31 ? nil : .x(m), scaleShift: loadAccessScale(dtype),
        )
        var draft = memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
        if firstFault { draft = markFirstFault(draft) }
        return draft
    }

    /// LDNT1<msz> `{Zt.<T>}, Pg/z, [Xn{, #imm4, mul vl}]` (contiguous
    /// non-temporal, imm).
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
    @inline(__always)
    static func decodeStructuredImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (count, el, mn) = structuredForm(e) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memLoadDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// Structured register-offset load form `[Xn, Xm{, lsl #k}]`.
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

    /// SVE2p1 128-bit contiguous `ld1w`/`ld1d` `{Zt.q}, Pg/z, [Xn{, #imm, mul
    /// vl}]` (imm form, mk=001 bits[22:20]=001).
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

    /// LD1RQ<sz> / LD1RO<sz> `{Zt.<T>}, Pg/z, [Xn{, #imm}]` (quad/oct
    /// replicate, imm form).
    @inline(__always)
    static func decodeReplicateQuad(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let marker = (e >> 20) & 0b111
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

    /// The contiguous / structured / scatter / non-temporal store region and
    /// STR spill (0xE4/0xE5).
    @inline(__always)
    static func decodeStoreRegion(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 22) & 0x3FF == 0b11_1001_0110 {
            let mk0 = (e >> 13) & 0b111
            if mk0 == 0b010 || mk0 == 0b000 { return decodeFillSpill(e, a, isStore: true, &sink) }
        }
        switch (e >> 13) & 0b111 {
        case 0b010: return decodeContiguousStoreSS(e, a, &sink)
        case 0b011:
            return (e >> 21) & 0b11 == 0 ? decodeContiguousNTReg(e, a, isStore: true, &sink)
                : decodeStoreStructuredReg(e, a, &sink)
        case 0b111:
            return decodeStoreImmOrStructured(e, a, &sink)
        case 0b100: return decodeScatterSV(e, a, extend: .uxtw, &sink)
        case 0b101: return decodeScatterSV(e, a, extend: .none, &sink)
        case 0b110: return decodeScatterSV(e, a, extend: .sxtw, &sink)
        case 0b001: return decodeScatterNTOrQuad(e, a, &sink)
        default: return decodeStore128Structured(e, a, &sink)
        }
    }

    /// ST1<msz> `{Zt.<T>}, Pg, [Xn{, #imm4, mul vl}]` (cst_si), STNT1 imm, or
    /// structured est_si.
    @inline(__always)
    static func decodeStoreImmOrStructured(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 20) & 1 == 0 {
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

    /// Store structured `[Xn{, #imm, mul vl}]` (est_si).
    @inline(__always)
    static func decodeStoreStructuredImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let count = UInt8((e >> 21) & 0b11) + 1
        let el = esize(UInt8((e >> 23) & 0b11))
        let mn = structuredName(count: count, element: el, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e)
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// Store structured `[Xn, Xm{, lsl}]` (est_ss).
    @inline(__always)
    static func decodeStoreStructuredReg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        let count = UInt8((e >> 21) & 0b11) + 1
        let el = esize(UInt8((e >> 23) & 0b11))
        let mn = structuredName(count: count, element: el, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: elementScale(el))
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, groupCount: count, &sink)
    }

    /// 128-bit structured store ST2Q-4Q at mk=000 (0xE4 only, bit24=0).
    @inline(__always)
    static func decodeStore128Structured(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 24) & 1 == 0 else { return undefined(e, a) }
        let nregs = (e >> 22) & 0b11
        guard nregs != 0 else { return undefined(e, a) }
        let count = UInt8(nregs) + 1
        let mn = structuredName(count: count, element: .q, isStore: true)
        let t = rd(e), g = pg3(e), n = rn(e)
        if (e >> 21) & 1 == 1 {
            guard rm(e) != 31 else { return undefined(e, a) }
            let addr = ScalableMemoryOperand(base: .gpr(.x(n)), scalarIndex: .x(rm(e)), scaleShift: 4)
            return memStoreDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, groupCount: count, &sink)
        }
        guard (e >> 20) & 1 == 0 else { return undefined(e, a) }
        let imm = signExtend4((e >> 16) & 0xF) &* Int32(count)
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm, mulVL: true)
        return memStoreDraft(e, a, mn: mn, zt: t, el: .q, g: g, addr: addr, groupCount: count, &sink)
    }

    /// ST1<dtype> `{Zt.<T>}, Pg, [Xn, Xm{, lsl}]` (cst_ss).
    @inline(__always)
    static func decodeContiguousStoreSS(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard rm(e) != 31 else { return undefined(e, a) }
        let dtype = UInt8((e >> 21) & 0xF)
        guard let (mn, el) = storeDtype(dtype) else { return undefined(e, a) }
        let t = rd(e), g = pg3(e), n = rn(e), m = rm(e)
        let msz = UInt8((e >> 23) & 0b11)
        let addr = ScalableMemoryOperand(
            base: .gpr(.x(n)), scalarIndex: .x(m), scaleShift: msz,
        )
        return memStoreDraft(e, a, mn: mn, zt: t, el: el, g: g, addr: addr, &sink)
    }

    /// LDR/STR register fill/spill decode.
    @inline(__always)
    static func decodeFillSpill(_ e: UInt32, _ a: UInt64, isStore: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let isPred = (e >> 13) & 0b111 == 0b000
        if isPred, (e >> 4) & 1 != 0 { return undefined(e, a) }
        let t = rd(e), n = rn(e)
        let imm9 = signExtend9(((e >> 16) & 0x3F) << 3 | ((e >> 10) & 0x7))
        let addr = ScalableMemoryOperand(base: .gpr(.x(n)), displacement: imm9, mulVL: true)
        let data: Operand = isPred
            ? .scalablePredicate(ScalablePredicateRef(registerIndex: t & 0xF, role: .governing))
            : vecPlain(t)
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

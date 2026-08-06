// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodePredicatedArithLog(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let mnemonic = predicatedArithLogMnemonic((e >> 16) & 0b11111, sz: (e >> 22) & 0b11) else {
            return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .merging), vec(d, size), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// opc[20:16] × sz → mnemonic for `sve_int_bin_pred_arit_log`.
    @inline(__always)
    static func predicatedArithLogMnemonic(_ opc: UInt32, sz: UInt32) -> Mnemonic? {
        switch opc {
        case 0x00: .add
        case 0x01: .sub
        case 0x03: .subr
        case 0x04: sz == 0b11 ? .addpt : nil
        case 0x05: sz == 0b11 ? .subpt : nil
        case 0x08: .smax
        case 0x09: .umax
        case 0x0A: .smin
        case 0x0B: .umin
        case 0x0C: .sabd
        case 0x0D: .uabd
        case 0x10: .mul
        case 0x12: .smulh
        case 0x13: .umulh
        case 0x14: sz == 0b10 || sz == 0b11 ? .sdiv : nil
        case 0x15: sz == 0b10 || sz == 0b11 ? .udiv : nil
        case 0x16: sz == 0b10 || sz == 0b11 ? .sdivr : nil
        case 0x17: sz == 0b10 || sz == 0b11 ? .udivr : nil
        case 0x18: .orr
        case 0x19: .eor
        case 0x1A: .and
        case 0x1B: .bic
        default: nil
        }
    }

    @inline(__always)
    static func decodePredicatedUnary(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let merging = (e >> 20) & 1 == 1
        guard let mnemonic = predicatedUnaryMnemonic((e >> 16) & 0b1111, sz: (e >> 22) & 0b11) else {
            return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        var reads = vecMask(n)
        var effect: ScalableEffect = .readsStreamingMode
        if merging {
            reads = reads.union(vecMask(d))
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, merging ? .merging : .zeroing), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: effect,
        )
    }

    /// opc[19:16] × sz → mnemonic for the predicated unary family.
    @inline(__always)
    static func predicatedUnaryMnemonic(_ opc: UInt32, sz: UInt32) -> Mnemonic? {
        switch opc {
        case 0x0: sz >= 0b01 ? .sxtb : nil
        case 0x1: sz >= 0b01 ? .uxtb : nil
        case 0x2: sz >= 0b10 ? .sxth : nil
        case 0x3: sz >= 0b10 ? .uxth : nil
        case 0x4: sz == 0b11 ? .sxtw : nil
        case 0x5: sz == 0b11 ? .uxtw : nil
        case 0x6: .abs
        case 0x7: .neg
        case 0x8: .cls
        case 0x9: .clz
        case 0xA: .cnt
        case 0xB: .cnot
        case 0xE: .not
        default: nil
        }
    }

    @inline(__always)
    static func decodeMultiplyAddMLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let da = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        let mnemonic: Mnemonic = (e >> 13) & 1 == 0 ? .mla : .mls
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, size), govern(g, .merging), vec(n, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeMultiplyAddMAD(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dn = zd(e), m = zm(e), za = zn(e), g = pg3(e), size = sz(e)
        let mnemonic: Mnemonic = (e >> 13) & 1 == 0 ? .mad : .msb
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)).union(vecMask(za)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), govern(g, .merging), vec(m, size), vec(za, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeReduction(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 18) & 1 == 1 {
            return decodeReductionQuadword(e, a, &sink)
        }
        guard let mnemonic = reductionMnemonic((e >> 16) & 0b11111) else { return undefined(e, a) }
        let vd = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        if mnemonic == .saddv, size == .d { return undefined(e, a) }
        let destSize: ScalarSize = mnemonic == .saddv || mnemonic == .uaddv ? .d : size
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(vd), category: .sve,
            operandCount: sink.emit(.vectorRegister(VectorRegisterRef(registerIndex: vd, view: .scalar(size: destSize))), govern(g, .none), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// opc[20:16] → mnemonic for `sve_int_reduce`.
    @inline(__always)
    static func reductionMnemonic(_ opc: UInt32) -> Mnemonic? {
        switch opc {
        case 0x00: .saddv
        case 0x01: .uaddv
        case 0x08: .smaxv
        case 0x09: .umaxv
        case 0x0A: .sminv
        case 0x0B: .uminv
        case 0x18: .orv
        case 0x19: .eorv
        case 0x1A: .andv
        default: nil
        }
    }

    /// `<mn> <Vd>.<arr>, <Pg>, <Zn>.<T>`.
    @inline(__always)
    static func decodeReductionQuadword(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b11111 {
        case 0b00101: mnemonic = .addqv
        case 0b01100: mnemonic = .smaxqv
        case 0b01101: mnemonic = .umaxqv
        case 0b01110: mnemonic = .sminqv
        case 0b01111: mnemonic = .uminqv
        case 0b11100: mnemonic = .orqv
        case 0b11101: mnemonic = .eorqv
        case 0b11110: mnemonic = .andqv
        default: return undefined(e, a)
        }
        let size = sz(e)
        let arrangement: VectorArrangement = switch size {
        case .b: .b16
        case .h: .h8
        case .s: .s4
        default: .d2
        }
        let vd = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(vd), category: .sve,
            operandCount: sink.emit(.vectorRegister(VectorRegisterRef(registerIndex: vd, view: .full(arrangement: arrangement))), govern(g, .none), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodePredicatedShift(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 20) & 1 == 0 { return decodePredicatedShiftImmediate(e, a, &sink) }
        if (e >> 19) & 1 == 1 { return decodePredicatedShiftWide(e, a, &sink) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .asr
        case 0b001: mnemonic = .lsr
        case 0b011: mnemonic = .lsl
        case 0b100: mnemonic = .asrr
        case 0b101: mnemonic = .lsrr
        case 0b111: mnemonic = .lslr
        default: return undefined(e, a)
        }
        return predicatedShiftRegisterDraft(e, a, mnemonic: mnemonic, wide: false, &sink)
    }

    @inline(__always)
    static func decodePredicatedShiftWide(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if sz(e) == .d { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .asr
        case 0b001: mnemonic = .lsr
        case 0b011: mnemonic = .lsl
        default: return undefined(e, a)
        }
        return predicatedShiftRegisterDraft(e, a, mnemonic: mnemonic, wide: true, &sink)
    }

    /// Shared predicated register/wide shift draft.
    @inline(__always)
    static func predicatedShiftRegisterDraft(_ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, wide: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), m = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .merging), vec(d, size), vec(m, wide ? .d : size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodePredicatedShiftImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let selector = (((e >> 19) & 1) << 3) | ((e >> 16) & 0b111)
        let (mnemonic, isLeft): (Mnemonic, Bool)
        switch selector {
        case 0b0000: (mnemonic, isLeft) = (.asr, false)
        case 0b0001: (mnemonic, isLeft) = (.lsr, false)
        case 0b0011: (mnemonic, isLeft) = (.lsl, true)
        case 0b0100: (mnemonic, isLeft) = (.asrd, false)
        case 0b0110: (mnemonic, isLeft) = (.sqshl, true)
        case 0b0111: (mnemonic, isLeft) = (.uqshl, true)
        case 0b1100: (mnemonic, isLeft) = (.srshr, false)
        case 0b1101: (mnemonic, isLeft) = (.urshr, false)
        case 0b1111: (mnemonic, isLeft) = (.sqshlu, true)
        default: return undefined(e, a)
        }
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 5) & 0b11111, lowBits: 5) else {
            return undefined(e, a)
        }
        let amount = isLeft ? Int64(tsz) - Int64(esize) : 2 * Int64(esize) - Int64(tsz)
        let d = zd(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), govern(g, .merging), vec(d, element), .immediate(value: amount, width: 8)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}

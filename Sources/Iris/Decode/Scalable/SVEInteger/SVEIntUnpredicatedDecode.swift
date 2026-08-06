// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeUnpredicated(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 12) & 0b1111 {
        case 0b0000, 0b0001: decodeUnpredicatedArith(e, a, &sink)
        case 0b0110, 0b0111: decodeUnpredicatedMul(e, a, &sink)
        case 0b1000: decodeUnpredicatedShiftWide(e, a, &sink)
        case 0b0011: decodeUnpredicatedLogicalOrTernary(e, a, &sink)
        case 0b1001: decodeUnpredicatedShiftImm(e, a, &sink)
        case 0b1010: decodeAddressGeneration(e, a, &sink)
        default: undefined(e, a)
        }
    }

    /// A plain unpredicated three-register form `<mn> Zd.T, Zn.T, Zm.T`.
    @inline(__always)
    static func unpredicatedZZZ(_ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, size: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeUnpredicatedArith(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 10) & 0b111 {
        case 0b000: mnemonic = .add
        case 0b001: mnemonic = .sub
        case 0b010: guard sz(e) == .d else { return undefined(e, a) }; mnemonic = .addpt
        case 0b011: guard sz(e) == .d else { return undefined(e, a) }; mnemonic = .subpt
        case 0b100: mnemonic = .sqadd
        case 0b101: mnemonic = .uqadd
        case 0b110: mnemonic = .sqsub
        default: mnemonic = .uqsub
        }
        return unpredicatedZZZ(e, a, mnemonic: mnemonic, size: sz(e), &sink)
    }

    @inline(__always)
    static func decodeUnpredicatedMul(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 10) & 0b111 == 0b001, sz(e) != .b { return undefined(e, a) }
        let mnemonic: Mnemonic = switch (e >> 10) & 0b111 {
        case 0b000: .mul
        case 0b001: .pmul
        case 0b010: .smulh
        case 0b011: .umulh
        case 0b100: .sqdmulh
        case 0b101: .sqrdmulh
        case 0b110: .addqp
        default: .addsubp
        }
        return unpredicatedZZZ(e, a, mnemonic: mnemonic, size: sz(e), &sink)
    }

    @inline(__always)
    static func decodeUnpredicatedShiftWide(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = sz(e)
        if size == .d { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 10) & 0b11 {
        case 0b00: mnemonic = .asr
        case 0b01: mnemonic = .lsr
        case 0b11: mnemonic = .lsl
        default: return undefined(e, a)
        }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, .d)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeUnpredicatedLogicalOrTernary(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 10) & 0b11 == 0 else { return decodeTernary(e, a, &sink) }
        let d = zd(e), n = zn(e), m = zm(e)
        let mnemonic: Mnemonic
        switch (e >> 22) & 0b11 {
        case 0b00: mnemonic = .and
        case 0b01:
            if n == m {
                return DecodedDraft(
                    address: a, encoding: e, mnemonic: .mov,
                    semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
                    operandCount: sink.emit(vec(d, .d), vec(n, .d)), scalableEffect: .readsStreamingMode,
                )
            }
            mnemonic = .orr
        case 0b10: mnemonic = .eor
        default: mnemonic = .bic
        }
        return unpredicatedZZZ(e, a, mnemonic: mnemonic, size: .d, &sink)
    }

    @inline(__always)
    static func decodeUnpredicatedShiftImm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        let isLeft: Bool
        switch (e >> 10) & 0b11 {
        case 0b00: mnemonic = .asr; isLeft = false
        case 0b01: mnemonic = .lsr; isLeft = false
        case 0b11: mnemonic = .lsl; isLeft = true
        default: return undefined(e, a)
        }
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5) else {
            return undefined(e, a)
        }
        let amount = isLeft ? Int64(tsz) - Int64(esize) : 2 * Int64(esize) - Int64(tsz)
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), vec(n, element), .immediate(value: amount, width: 8)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeAddressGeneration(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let element: ScalarSize
        let extend: ExtendKind
        switch (e >> 22) & 0b11 {
        case 0b00: element = .d; extend = .sxtw
        case 0b01: element = .d; extend = .uxtw
        case 0b10: element = .s; extend = .lsl
        default: element = .d; extend = .lsl
        }
        let d = zd(e), n = zn(e), m = zm(e)
        let shift = (e >> 10) & 0b11
        let mem = ScalableMemoryOperand(
            base: .vector(ScalableVectorRef(registerIndex: n, element: element)),
            index: ScalableVectorRef(registerIndex: m, element: element),
            indexExtend: extend, scaleShift: UInt8(shift),
        )
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .adr,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), .scalableMemory(mem)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeTernary(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 11) & 1 == 0 { return decodeRotateXor(e, a, &sink) }
        let mnemonic: Mnemonic
        switch (((e >> 22) & 0b11) << 1) | ((e >> 10) & 1) {
        case 0b000: mnemonic = .eor3
        case 0b001: mnemonic = .bsl
        case 0b010: mnemonic = .bcax
        case 0b011: mnemonic = .bsl1n
        case 0b101: mnemonic = .bsl2n
        case 0b111: mnemonic = .nbsl
        default: return undefined(e, a)
        }
        let dn = zd(e), m = zm(e), k = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)).union(vecMask(k)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, .d), vec(dn, .d), vec(m, .d), vec(k, .d)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeRotateXor(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let dn = zd(e), m = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .xar,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, element), vec(dn, element), vec(m, element), .immediate(value: 2 * Int64(esize) - Int64(tsz), width: 8)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

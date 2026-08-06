// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeSVE2High(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch e & 0xFFFF_E420 {
        case 0x4531_4000: return decodeMultiVectorExtractNarrow(e, a, &sink)
        default: break
        }
        switch e & 0xFF3E_F800 {
        case 0x4500_D800: return decodeComplexAddition(e, a, &sink)
        default: break
        }
        switch e & 0xFFE0_FC00 {
        case 0x4520_A000: return decodeHistogramSegment(e, a, &sink)
        default: break
        }
        switch e & 0xFFA7_E400 {
        case 0x4520_4000: return decodeSaturatingExtractNarrow(e, a, top: false, &sink)
        case 0x4520_4400: return decodeSaturatingExtractNarrow(e, a, top: true, &sink)
        default: break
        }
        switch e & 0xFFE0_C420 {
        case 0x45A0_0000: return decodeMultiVectorShiftNarrow(e, a, &sink)
        default: break
        }
        switch e & 0xFF20_FC00 {
        case 0x4500_9800: return decodeIntegerMatmul(e, a, &sink)
        default: break
        }
        switch e & 0xFFA0_F000 {
        case 0x4500_A000: return decodeShiftLeftLong(e, a, &sink)
        default: break
        }
        switch e & 0xFF20_F800 {
        case 0x4500_9000: return decodeXorInterleaved(e, a, &sink)
        case 0x4500_F000: return decodeShiftInsert(e, a, &sink)
        default: break
        }
        switch e & 0xFFA0_E000 {
        case 0x4520_8000: return decodeCharacterMatch(e, a, &sink)
        case 0x45A0_C000: return decodeHistogramCount(e, a, &sink)
        default: break
        }
        switch e & 0xFF20_E400 {
        case 0x4520_6000: return decodeAddSubNarrowHigh(e, a, top: false, &sink)
        case 0x4520_6400: return decodeAddSubNarrowHigh(e, a, top: true, &sink)
        default: break
        }
        switch e & 0xFF20_F000 {
        case 0x4500_E000: return decodeAccumulateShift(e, a, &sink)
        default: break
        }
        switch e & 0xFFA0_C400 {
        case 0x4520_0000: return decodeShiftNarrow(e, a, top: false, &sink)
        case 0x4520_0400: return decodeShiftNarrow(e, a, top: true, &sink)
        default: break
        }
        switch e & 0xFF20_C000 {
        case 0x4500_C000: return decodeAbsoluteDifferenceAccumulate(e, a, &sink)
        case 0x4500_8000: return decodeMiscellaneous(e, a, &sink)
        default: break
        }
        switch e & 0xFF20_8000 {
        case 0x4500_0000: return decodeWideIntegerArith(e, a, &sink)
        default: return undefined(e, a)
        }
    }

    /// The three operand shapes of the widening family.
    enum WideningShape { case long, wide, polynomial }

    @inline(__always)
    static func decodeWideIntegerArith(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (mnemonic, shape) = wideIntegerArithMnemonic((e >> 10) & 0b11111) else {
            return undefined(e, a)
        }
        let szf = (e >> 22) & 0b11
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
            operandCount: sink.emit(vec(d, dest), vec(n, shape == .wide ? dest : source), vec(m, source)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// opc[14:10] → mnemonic + shape for `sve2_wide_int_arith`.
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

    @inline(__always)
    static func decodeMiscellaneous(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let d = zd(e), n = zn(e), m = zm(e)
        let mnemonic: Mnemonic
        switch (e >> 10) & 0b1111 {
        case 0b1100: mnemonic = .bext
        case 0b1101: mnemonic = .bdep
        case 0b1110: mnemonic = .bgrp
        case 0b0000, 0b0010, 0b0011:
            guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
            let long: Mnemonic = switch (e >> 10) & 0b1111 {
            case 0b0000: .saddlbt
            case 0b0010: .ssublbt
            default: .ssubltb
            }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: long,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, elementSize(szf)), vec(n, source), vec(m, source)),
                scalableEffect: .readsStreamingMode,
            )
        default: return undefined(e, a)
        }
        return unpredicatedZZZ(e, a, mnemonic: mnemonic, size: elementSize(szf), &sink)
    }

    @inline(__always)
    static func decodeXorInterleaved(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), n = zn(e), m = zm(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 10) & 1 == 0 ? .eorbt : .eortb,
            semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// The absolute-difference-accumulate class straddles both SVE2 top bytes,
    /// b24 being part of its opcode.
    @inline(__always)
    static func decodeAbsoluteDifferenceAccumulate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let opc = (e >> 10) & 0b1111
        let mnemonic: Mnemonic
        let element: ScalarSize
        let source: ScalarSize

        if (e >> 24) & 1 == 0 {
            guard szf != 0, let narrow = narrower(elementSize(szf)) else { return undefined(e, a) }
            mnemonic = (e >> 11) & 1 == 0 ? .sabal : .uabal
            element = elementSize(szf)
            source = narrow
        } else {
            switch opc {
            case 0b0000, 0b0001, 0b0010, 0b0011:
                guard szf != 0, let narrow = narrower(elementSize(szf)) else { return undefined(e, a) }
                mnemonic = switch opc {
                case 0b0000: .sabalb
                case 0b0001: .sabalt
                case 0b0010: .uabalb
                default: .uabalt
                }
                element = elementSize(szf)
                source = narrow
            case 0b0100, 0b0101:
                let top = opc == 0b0101
                mnemonic = (e >> 23) & 1 == 0
                    ? (top ? .adclt : .adclb)
                    : (top ? .sbclt : .sbclb)
                element = (e >> 22) & 1 == 1 ? .d : .s
                source = element
            case 0b1110, 0b1111:
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
            operandCount: sink.emit(vec(da, element), vec(n, source), vec(m, source)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeIntegerMatmul(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 22) & 0b11 {
        case 0b00: mnemonic = .smmla
        case 0b10: mnemonic = .usmmla
        case 0b11: mnemonic = .ummla
        default: return undefined(e, a)
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, .s), vec(n, .b), vec(m, .b)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeAccumulateShift(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: .ssra
        case 0b01: .usra
        case 0b10: .srsra
        default: .ursra
        }
        let da = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, element), vec(n, element), .immediate(value: 2 * Int64(esize) - Int64(tsz), width: 8)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeShiftInsert(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let left = (e >> 10) & 1 == 1
        let amount = left ? Int64(tsz) - Int64(esize) : 2 * Int64(esize) - Int64(tsz)
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: left ? .sli : .sri,
            semanticReads: vecMask(d).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), vec(n, element), .immediate(value: amount, width: 8)),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeShiftLeftLong(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (source, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 1, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let dest: ScalarSize = source == .b ? .h : source == .h ? .s : .d
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: .sshllb
        case 0b01: .sshllt
        case 0b10: .ushllb
        default: .ushllt
        }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, source), .immediate(value: Int64(tsz) - Int64(esize), width: 8)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeComplexAddition(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dn = zd(e), size = sz(e)
        let m = zn(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 16) & 1 == 0 ? .cadd : .sqcadd,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), vec(dn, size), vec(m, size), .immediate(value: (e >> 10) & 1 == 0 ? 90 : 270, width: 16)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCharacterMatch(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let pd = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 4) & 1 == 0 ? .match : .nmatch,
            semanticReads: vecMask(n).union(vecMask(m)),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeHistogramCount(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .histcnt,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .zeroing), vec(n, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeHistogramSegment(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        unpredicatedZZZ(e, a, mnemonic: .histseg, size: .b, &sink)
    }
}

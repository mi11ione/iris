// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeMove(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e & 0xFF3F_FC00) == 0x0520_3800 { return decodeDupScalar(e, a, &sink) }
        if (e & 0xFF20_FC00) == 0x0520_2000 { return decodeDupIndexed(e, a, &sink) }
        if (e & 0xFF3F_E000) == 0x0528_A000 { return decodeCpyScalar(e, a, &sink) }
        if (e & 0xFF3F_E000) == 0x0520_8000 { return decodeCpySimd(e, a, &sink) }
        if (e & 0xFF30_8000) == 0x0510_0000 { return decodeCpyImmediate(e, a, &sink) }
        return decodeLogicalImmediate(e, a, &sink)
    }

    /// The GPR width for a scalable move scalar source.
    @inline(__always)
    static func moveScalarGPR(_ index: UInt8, _ size: ScalarSize) -> RegisterRef {
        if size == .d {
            return index == 31 ? .sp() : .x(index)
        }
        return index == 31 ? .wsp() : .w(index)
    }

    @inline(__always)
    static func decodeDupScalar(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), size = sz(e)
        let src = moveScalarGPR(zn(e), size)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: RegisterSet.empty.inserting(src),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), .register(src)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCpyScalar(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), g = pg3(e), size = sz(e)
        let src = moveScalarGPR(zn(e), size)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: RegisterSet.empty.inserting(src).union(vecMask(d)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .merging), .register(src)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeCpySimd(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: vecMask(n).union(vecMask(d)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .merging), .vectorRegister(VectorRegisterRef(registerIndex: n, view: .scalar(size: size)))),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeCpyImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), size = sz(e)
        let g = UInt8((e >> 16) & 0xF)
        let merging = (e >> 14) & 1 == 1
        let raw = (e >> 5) & 0xFF
        if (e >> 13) & 1 == 1, size == .b { return undefined(e, a) }
        let shift: UInt32 = (e >> 13) & 1 == 1 ? 8 : 0
        let operandMark = sink.mark
        sink.append(vec(d, size))
        sink.append(govern(g, merging ? .merging : .zeroing))
        appendShiftedImmediate(raw: raw, shift: shift, signed: true, to: &sink)
        var reads = RegisterSet.empty
        var effect: ScalableEffect = .readsStreamingMode
        if merging { reads = vecMask(d); effect.insert(.partialWrite) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: reads, semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.count(since: operandMark),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: effect,
        )
    }

    @inline(__always)
    static func decodeDupIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let tsz = (((e >> 22) & 0b11) << 5) | ((e >> 16) & 0b11111)
        guard tsz != 0 else { return undefined(e, a) }
        let element: ScalarSize
        switch tsz.trailingZeroBitCount {
        case 0: element = .b
        case 1: element = .h
        case 2: element = .s
        case 3: element = .d
        case 4: element = .q
        default: return undefined(e, a)
        }
        let index = tsz >> (UInt32(tsz.trailingZeroBitCount) + 1)
        let d = zd(e), n = zn(e)
        let source: Operand = index == 0
            ? .vectorRegister(VectorRegisterRef(registerIndex: n, view: .scalar(size: element)))
            : .scalableVector(ScalableVectorRef(registerIndex: n, element: element, elementIndex: UInt8(index)))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, element), source),
            scalableEffect: .readsStreamingMode,
        )
    }
}

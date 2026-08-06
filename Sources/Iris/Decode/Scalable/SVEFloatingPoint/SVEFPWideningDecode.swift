// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeWideningMLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16 = (e >> 22) & 1 == 1
        let subtract = (e >> 13) & 1 == 1
        let top = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic = bf16
            ? (subtract ? (top ? .bfmlslt : .bfmlslb) : (top ? .bfmlalt : .bfmlalb))
            : (subtract ? (top ? .fmlslt : .fmlslb) : (top ? .fmlalt : .fmlalb))
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, .s), vec(n, .h), vec(m, .h)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeWideningMLAIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16 = (e >> 22) & 1 == 1
        let subtract = (e >> 13) & 1 == 1
        let top = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic = bf16
            ? (subtract ? (top ? .bfmlslt : .bfmlslb) : (top ? .bfmlalt : .bfmlalb))
            : (subtract ? (top ? .fmlslt : .fmlslb) : (top ? .fmlalt : .fmlalb))
        let laneBits: UInt32 = ((e >> 18) & 0b100) | ((e >> 18) & 0b010) | ((e >> 11) & 0b001)
        let lane = UInt8(laneBits)
        let da = zd(e), n = zn(e)
        let m = UInt8((e >> 16) & 0b111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, .s), vec(n, .h), vecIndexed(m, .h, lane: lane)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeDot(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16Source = (e >> 22) & 1 == 1
        let mnemonic: Mnemonic
        let dest: ScalarSize
        let src: ScalarSize
        if (e >> 10) & 1 == 0 {
            mnemonic = bf16Source ? .bfdot : .fdot
            dest = .s
            src = .h
        } else {
            mnemonic = .fdot
            dest = bf16Source ? .s : .h
            src = .b
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, src), vec(m, src)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeDotIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 22) & 1 == 1 ? .bfdot : .fdot
        let lane = UInt8((e >> 19) & 0b11)
        let da = zd(e), n = zn(e)
        let m = UInt8((e >> 16) & 0b111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, .s), vec(n, .h), vecIndexed(m, .h, lane: lane)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFP8DotIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dest: ScalarSize
        let lane: UInt8
        if (e >> 22) & 1 == 1 {
            if (e >> 11) & 1 != 0 { return undefined(e, a) }
            dest = .s
            lane = UInt8((e >> 19) & 0b11)
        } else {
            dest = .h
            let laneBits: UInt32 = ((e >> 18) & 0b100) | ((e >> 18) & 0b010) | ((e >> 11) & 0b001)
            lane = UInt8(laneBits)
        }
        let da = zd(e), n = zn(e)
        let m = UInt8((e >> 16) & 0b111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fdot,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, .b), vecIndexed(m, .b, lane: lane)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFP8MLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        let dest: ScalarSize
        if (e >> 23) & 1 == 1 {
            if (e >> 13) & 1 != 0 { return undefined(e, a) }
            mnemonic = (e >> 12) & 1 == 0 ? .fmlalb : .fmlalt
            dest = .h
        } else {
            switch (e >> 12) & 0b11 {
            case 0b00: mnemonic = .fmlallbb
            case 0b01: mnemonic = .fmlallbt
            case 0b10: mnemonic = .fmlalltb
            default: mnemonic = .fmlalltt
            }
            dest = .s
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, .b), vec(m, .b)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFP8LongIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 23) & 1 == 0 ? .fmlalb : .fmlalt
        return fp8IndexedDraft(e, a, mnemonic, dest: .h, &sink)
    }

    @inline(__always)
    static func decodeFP8LongLongIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = switch (e >> 22) & 0b11 {
        case 0b00: .fmlallbb
        case 0b01: .fmlallbt
        case 0b10: .fmlalltb
        default: .fmlalltt
        }
        return fp8IndexedDraft(e, a, mnemonic, dest: .s, &sink)
    }

    /// The FP8 indexed multiply-add shape.
    @inline(__always)
    static func fp8IndexedDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, dest: ScalarSize, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let laneBits: UInt32 = ((e >> 17) & 0b1100) | ((e >> 10) & 0b0011)
        let lane = UInt8(laneBits)
        let da = zd(e), n = zn(e)
        let m = UInt8((e >> 16) & 0b111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, .b), vecIndexed(m, .b, lane: lane)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeMatrixMLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let key = ((e >> 21) & 0b110) | ((e >> 10) & 0b001)
        let mnemonic: Mnemonic
        let dest: ScalarSize
        let src: ScalarSize
        switch key {
        case 0b000: (mnemonic, dest, src) = (.fmmla, .s, .b)
        case 0b001: (mnemonic, dest, src) = (.fmmla, .s, .h)
        case 0b010: (mnemonic, dest, src) = (.fmmla, .h, .b)
        case 0b011: (mnemonic, dest, src) = (.bfmmla, .s, .h)
        case 0b100: (mnemonic, dest, src) = (.fmmla, .h, .h)
        case 0b101: (mnemonic, dest, src) = (.fmmla, .s, .s)
        case 0b110: (mnemonic, dest, src) = (.bfmmla, .h, .h)
        default: (mnemonic, dest, src) = (.fmmla, .d, .d)
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, src), vec(m, src)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

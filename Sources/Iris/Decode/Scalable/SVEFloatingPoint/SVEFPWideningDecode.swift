// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the widening multiply/dot/matrix cluster at 0x64 bit21=1:
// G19 FP16→FP32 and bf16 long multiply-add (FMLALB/T, FMLSLB/T, BFMLALB/T,
// BFMLSLB/T; vector and indexed — B/T selects INPUT halves, so every form
// is a full write), G20 dot products (FDOT/BFDOT vector + indexed + the FP8
// dot forms), G21 the FP8 multiply-add families (FMLALB/T H←B,
// FMLALLBB/BT/TB/TT S←B, vector and indexed), and the merged G21d/G22
// matrix multiply-accumulate region — one eight-slot table over
// (bits[23:22], bit10) spanning the FP8, F16F32MM, BF16, F16MM, F32MM,
// B16MM, and F64MM forms. Every form is an unpredicated accumulator:
// destination read, `partialWrite` clear.

extension SVEFloatingPointDecode {
    // MARK: G19a — widening MLA vector (bits[15:14]=10, bits[12:11]=00, bit23=1)

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

    // MARK: G19b — widening MLA indexed (bit23=1, bit15=0, bit14=1, bit12=0)

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

    // MARK: G20a — dot products, vector (bit23=0, bits[15:11]=10000)

    @inline(__always)
    static func decodeDot(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16Source = (e >> 22) & 1 == 1
        let mnemonic: Mnemonic
        let dest: ScalarSize
        let src: ScalarSize
        if (e >> 10) & 1 == 0 {
            // Half-precision sources.
            mnemonic = bf16Source ? .bfdot : .fdot
            dest = .s
            src = .h
        } else {
            // FP8 byte sources; bit22 selects the destination width.
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

    // MARK: G20b — dot products, indexed (bit23=0, bits[15:10]=010000)

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

    // MARK: G20c — FP8 dot indexed (bit23=0, bits[15:12]=0100, bit10=1)

    @inline(__always)
    static func decodeFP8DotIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let dest: ScalarSize
        let lane: UInt8
        if (e >> 22) & 1 == 1 {
            // S destination: 2-bit index, bit11 fixed zero.
            if (e >> 11) & 1 != 0 { return undefined(e, a) }
            dest = .s
            lane = UInt8((e >> 19) & 0b11)
        } else {
            // H destination: 3-bit index spanning bits[20:19] and bit11.
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

    // MARK: G21a — FP8 MLA vector (bit22=0, bits[15:14]=10, bits[11:10]=10)

    @inline(__always)
    static func decodeFP8MLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        let dest: ScalarSize
        if (e >> 23) & 1 == 1 {
            // Long: H ← B, bottom/top by bit12 (bit13 fixed zero).
            if (e >> 13) & 1 != 0 { return undefined(e, a) }
            mnemonic = (e >> 12) & 1 == 0 ? .fmlalb : .fmlalt
            dest = .h
        } else {
            // Long-long: S ← B, the four B/T combinations at bits[13:12].
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

    // MARK: G21b — FP8 long MLA indexed (bit22=0, bits[15:12]=0101)

    @inline(__always)
    static func decodeFP8LongIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 23) & 1 == 0 ? .fmlalb : .fmlalt
        return fp8IndexedDraft(e, a, mnemonic, dest: .h, &sink)
    }

    // MARK: G21c — FP8 long-long MLA indexed (bits[15:12]=1100)

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

    /// The FP8 indexed multiply-add shape: byte sources, a 4-bit element
    /// index packed as bits[20:19]:bits[11:10], and a 3-bit Zm.
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

    // MARK: G21d/G22 — matrix MLA (bit21=1, bits[15:11]=11100)

    @inline(__always)
    static func decodeMatrixMLA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // One eight-slot table over (bits[23:22], bit10) spanning the FP8,
        // widening, and same-size matrix forms.
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

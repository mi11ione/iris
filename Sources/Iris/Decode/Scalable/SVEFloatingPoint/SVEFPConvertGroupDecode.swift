// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeFP8ConvertSingle(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let odd = (e >> 16) & 1 == 1
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: odd ? .f1cvtlt : .f1cvt
        case 0b01: odd ? .f2cvtlt : .f2cvt
        case 0b10: odd ? .bf1cvtlt : .bf1cvt
        default: odd ? .bf2cvtlt : .bf2cvt
        }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, .h), vec(n, .b)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFP8DownConvertPair(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 5) & 1 != 0 { return undefined(e, a) }
        let mnemonic: Mnemonic
        let src: ScalarSize
        var preserving = false
        switch (e >> 10) & 0b11 {
        case 0b00: (mnemonic, src) = (.fcvtn, .h)
        case 0b01: (mnemonic, src) = (.fcvtnb, .s)
        case 0b10: (mnemonic, src) = (.bfcvtn, .h)
        default:
            (mnemonic, src) = (.fcvtnt, .s)
            preserving = true
        }
        let d = zd(e)
        var reads = vecPairMask(e)
        var effect: ScalableEffect = .readsStreamingMode
        if preserving {
            reads = reads.union(vecMask(d))
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, .b), vecPair(e, src)),
            scalableEffect: effect,
        )
    }

    @inline(__always)
    static func decodeFP8UpConvert(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let dest = fpSize(e) else { return undefined(e, a) }
        let src = narrowerElement(dest)
        let mnemonic: Mnemonic = switch (e >> 10) & 0b11 {
        case 0b00: .scvtf
        case 0b01: .ucvtf
        case 0b10: .scvtflt
        default: .ucvtflt
        }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, src)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeIntConvertPair(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 5) & 1 != 0 { return undefined(e, a) }
        guard let src = fpSize(e) else { return undefined(e, a) }
        let dest = narrowerElement(src)
        let mnemonic: Mnemonic = (e >> 10) & 1 == 0 ? .fcvtzsn : .fcvtzun
        let d = zd(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecPairMask(e),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vecPair(e, src)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// The element size one step below `size`.
    @inline(__always)
    static func narrowerElement(_ size: ScalarSize) -> ScalarSize {
        switch size {
        case .s: .h
        case .d: .s
        default: .b
        }
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// G13, the FP8 and multi-vector convert cluster at 0x65
// (bits[15:12]=0011): single-source FP8 up-converts to half precision
// (F1CVT/F2CVT/BF1CVT/BF2CVT and their odd-input LT twins), the pair
// down-converts to FP8 bytes (FCVTN/FCVTNB/BFCVTN and the top-half FCVTNT —
// the one preserving form in the cluster), the FP8 integer up-converts
// (SCVTF/UCVTF ± LT from bytes), and the SVE2p2 pair int down-converts
// (FCVTZSN/FCVTZUN). Pair sources are consecutive `{ Z(2n), Z(2n+1) }`
// groups with the base register field at bits[9:6] and bit5 fixed zero.

extension SVEFloatingPointDecode {
    // MARK: G13a — FP8 convert single (bits[23:17]=0000100)

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

    // MARK: G13b/G13c — pair down-converts to FP8 (bits[23:16]=0x0A)

    @inline(__always)
    static func decodeFP8DownConvertPair(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // bit5 is a fixed zero field below the 4-bit pair base.
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
            preserving = true // top halves written, the rest of Zd survives
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

    // MARK: G13e — FP8 integer up-converts (bits[21:16]=001100)

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

    // MARK: G13d — pair int down-converts (bits[21:16]=001101, bits[15:11]=00110)

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

    /// The element size one step below `size` — the byte/half/single source
    /// of the FP8/pair convert forms. Callers derive `size` from ``fpSize``, so
    /// it is only ever `.h`/`.s`/`.d`; `.b`/`.q` never reach this helper.
    @inline(__always)
    static func narrowerElement(_ size: ScalarSize) -> ScalarSize {
        switch size {
        case .s: .h
        case .d: .s
        default: .b // .h → .b
        }
    }
}

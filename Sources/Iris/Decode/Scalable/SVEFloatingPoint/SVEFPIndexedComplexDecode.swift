// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeFCADD(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 17) & 0xF != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let rotation: Int64 = (e >> 16) & 1 == 0 ? 90 : 270
        let dn = zd(e), m = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcadd,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size), .immediate(value: rotation, width: 16)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeFCMLAVector(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let rotation = Int64((e >> 13) & 0b11) &* 90
        let da = zd(e), n = zn(e), m = zm(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcmla,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, size), govern(g, .merging), vec(n, size), vec(m, size), .immediate(value: rotation, width: 16)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeFCMLAIndexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let rotation = Int64((e >> 10) & 0b11) &* 90
        let da = zd(e), n = zn(e)
        let size: ScalarSize
        let m: UInt8
        let lane: UInt8
        if (e >> 22) & 1 == 0 {
            size = .h
            m = UInt8((e >> 16) & 0b111)
            lane = UInt8((e >> 19) & 0b11)
        } else {
            size = .s
            m = UInt8((e >> 16) & 0b1111)
            lane = UInt8((e >> 20) & 0b1)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcmla,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, size), vec(n, size), vecIndexed(m, size, lane: lane), .immediate(value: rotation, width: 16)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeIndexedFMA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16 = (e >> 11) & 1 == 1
        if bf16, (e >> 23) & 1 == 1 { return undefined(e, a) }
        let subtract = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic = bf16
            ? (subtract ? .bfmls : .bfmla)
            : (subtract ? .fmls : .fmla)
        return indexedMultiplyDraft(e, a, mnemonic, accumulate: true, &sink)
    }

    @inline(__always)
    static func decodeIndexedFMUL(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bf16 = (e >> 11) & 1 == 1
        if bf16, (e >> 23) & 1 == 1 { return undefined(e, a) }
        return indexedMultiplyDraft(e, a, bf16 ? .bfmul : .fmul, accumulate: false, &sink)
    }

    /// Build the `<Zd>.<T>, <Zn>.<T>, <Zm>.<T>[i]` draft with the per-size
    /// index packing the indexed FMA/FMUL forms share.
    @inline(__always)
    static func indexedMultiplyDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, accumulate: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let size: ScalarSize
        let m: UInt8
        let lane: UInt8
        if (e >> 23) & 1 == 0 {
            size = .h
            m = UInt8((e >> 16) & 0b111)
            let laneBits: UInt32 = ((e >> 20) & 0b100) | ((e >> 19) & 0b011)
            lane = UInt8(laneBits)
        } else if (e >> 22) & 1 == 0 {
            size = .s
            m = UInt8((e >> 16) & 0b111)
            lane = UInt8((e >> 19) & 0b11)
        } else {
            size = .d
            m = UInt8((e >> 16) & 0b1111)
            lane = UInt8((e >> 20) & 0b1)
        }
        let d = zd(e), n = zn(e)
        var reads = vecMask(n).union(vecMask(m))
        if accumulate { reads = reads.union(vecMask(d)) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vecIndexed(m, size, lane: lane)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

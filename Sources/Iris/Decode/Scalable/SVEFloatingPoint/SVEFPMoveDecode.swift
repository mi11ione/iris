// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeFDup(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let kind = immediateKind(size)
        let bits = vfpExpandImm(imm8: UInt8((e >> 5) & 0xFF), kind: kind)
        let d = zd(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fmov,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), .floatImmediate(bits: bits, kind: kind)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFCopy(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let kind = immediateKind(size)
        let bits = vfpExpandImm(imm8: UInt8((e >> 5) & 0xFF), kind: kind)
        let d = zd(e)
        let g = UInt8((e >> 16) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fmov,
            semanticReads: vecMask(d),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), govern(g, .merging), .floatImmediate(bits: bits, kind: kind)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}

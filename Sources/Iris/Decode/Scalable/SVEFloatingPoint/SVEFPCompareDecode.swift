// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeCompareVector(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let key = ((e >> 13) & 0b100) | ((e >> 12) & 0b010) | ((e >> 4) & 0b001)
        let mnemonic: Mnemonic
        switch key {
        case 0b000: mnemonic = .fcmge
        case 0b001: mnemonic = .fcmgt
        case 0b010: mnemonic = .fcmeq
        case 0b011: mnemonic = .fcmne
        case 0b100: mnemonic = .fcmuo
        case 0b101: mnemonic = .facge
        case 0b111: mnemonic = .facgt
        default: return undefined(e, a)
        }
        let pd = UInt8(e & 0xF), n = zn(e), m = zm(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCompareZero(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 18) & 1 != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let key = ((e >> 15) & 0b110) | ((e >> 4) & 0b001)
        let mnemonic: Mnemonic
        switch key {
        case 0b000: mnemonic = .fcmge
        case 0b001: mnemonic = .fcmgt
        case 0b010: mnemonic = .fcmlt
        case 0b011: mnemonic = .fcmle
        case 0b100: mnemonic = .fcmeq
        case 0b110: mnemonic = .fcmne
        default: return undefined(e, a)
        }
        let pd = UInt8(e & 0xF), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), .floatImmediate(bits: 0, kind: immediateKind(size))),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }
}

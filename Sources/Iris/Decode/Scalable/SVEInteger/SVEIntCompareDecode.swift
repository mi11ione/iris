// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeCompare(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 1 {
            return decodeCompareUnsignedImmediate(e, a, &sink)
        }
        let sel = (e >> 13) & 0b111
        let second = (e >> 4) & 1 == 1
        let (mnemonic, wide) = compareVectorMnemonic(sel, second: second)
        let pd = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        if wide, size == .d { return undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), vec(m, wide ? .d : size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// bits[15:13] × b4 → (mnemonic, isWide) for `sve_int_cmp`.
    @inline(__always)
    static func compareVectorMnemonic(_ sel: UInt32, second: Bool) -> (Mnemonic, Bool) {
        switch sel {
        case 0b000: (second ? .cmphi : .cmphs, false)
        case 0b001: (second ? .cmpne : .cmpeq, true)
        case 0b010: (second ? .cmpgt : .cmpge, true)
        case 0b011: (second ? .cmple : .cmplt, true)
        case 0b100: (second ? .cmpgt : .cmpge, false)
        case 0b101: (second ? .cmpne : .cmpeq, false)
        case 0b110: (second ? .cmphi : .cmphs, true)
        default: (second ? .cmpls : .cmplo, true)
        }
    }

    @inline(__always)
    static func decodeCompareUnsignedImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let pd = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        let second = (e >> 4) & 1 == 1
        let mnemonic: Mnemonic = (e >> 13) & 1 == 0
            ? (second ? .cmphi : .cmphs)
            : (second ? .cmpls : .cmplo)
        let imm = UInt64((e >> 14) & 0x7F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), .unsignedImmediate(value: imm, width: 7)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCompareSignedImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let pd = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        let second = (e >> 4) & 1 == 1
        let mnemonic: Mnemonic
        switch (e >> 13) & 0b111 {
        case 0b000: mnemonic = second ? .cmpgt : .cmpge
        case 0b001: mnemonic = second ? .cmple : .cmplt
        case 0b100: mnemonic = second ? .cmpne : .cmpeq
        default: return undefined(e, a)
        }
        let imm = signExtend((e >> 16) & 0x1F, bits: 5)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: size, role: .result)), govern(g, .zeroing), vec(n, size), .immediate(value: imm, width: 5)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableWrites: ScalableRegisterSet.empty.insertingPredicate(pd),
            scalableEffect: .readsStreamingMode,
        )
    }
}

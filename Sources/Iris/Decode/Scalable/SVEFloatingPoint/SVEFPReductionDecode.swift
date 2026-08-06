// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeFastReduction(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .faddv
        case 0b100: mnemonic = .fmaxnmv
        case 0b101: mnemonic = .fminnmv
        case 0b110: mnemonic = .fmaxv
        case 0b111: mnemonic = .fminv
        default: return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(.vectorRegister(VectorRegisterRef(registerIndex: d, view: .scalar(size: size))), govern(g, .none), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFADDA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 16) & 0b111 != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let dn = zd(e), m = zn(e), g = pg3(e)
        let scalar = Operand.vectorRegister(
            VectorRegisterRef(registerIndex: dn, view: .scalar(size: size)),
        )
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fadda,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(scalar, govern(g, .none), scalar, vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeQuadReduction(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 13) & 0b11 != 0b01 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .faddqv
        case 0b100: mnemonic = .fmaxnmqv
        case 0b101: mnemonic = .fminnmqv
        case 0b110: mnemonic = .fmaxqv
        case 0b111: mnemonic = .fminqv
        default: return undefined(e, a)
        }
        let arrangement: VectorArrangement = switch size {
        case .h: .h8
        case .s: .s4
        default: .d2
        }
        let d = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(.vectorRegister(VectorRegisterRef(registerIndex: d, view: .full(arrangement: arrangement))), govern(g, .none), vec(n, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }
}

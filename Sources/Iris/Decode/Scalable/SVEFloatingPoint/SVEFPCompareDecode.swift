// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP compare to predicate: G9 vector-register form
// (`sve_fp_3op_p_pd` — FCMEQ/FCMGE/FCMGT/FCMNE/FCMUO/FACGE/FACGT, selector
// (bit15, bit13, bit4)) and G10 compare-with-zero (`sve_fp_2op_p_pd` —
// FCMEQ/FCMGE/FCMGT/FCMLE/FCMLT/FCMNE against a literal `#0.0`, selector
// (bits[17:16], bit4)). Every compare writes its destination predicate and
// — the family's headline semantic, triple-sourced in the spec —
// NEVER touches NZCV: `flagEffect` stays `.none`, in deliberate contrast
// with SVE-integer's integer compares. The vector-register FCMLE/FCMLT/FACLE/FACLT
// spellings are assembler-only swapped-operand aliases and are never
// emitted; the zero-form FCMLE/FCMLT are real encodings and are.

extension SVEFloatingPointDecode {
    // MARK: G9 — vector compare (0x65, bit21=0, bit14=1)

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
        default: return undefined(e, a) // (1,1,0) — hole
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

    // MARK: G10 — compare with zero (0x65, bits[15:12]=0010, bits[20:19]=10)

    @inline(__always)
    static func decodeCompareZero(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // bit18 is a fixed zero field in this class.
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
        default: return undefined(e, a) // (10,1) and (11,1) — holes
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// G7 integer compare to predicate. Three encodings: vector/
// wide compare (`sve_int_cmp`, 0x24 bit21=0), unsigned-immediate compare
// (`sve_int_ucmp_vi`, 0x24 bit21=1), and signed-immediate compare
// (`sve_int_scmp_vi`, 0x25). All write a destination predicate AND NZCV
// (spec — the contrast with FP compares) and read a governing predicate
// under `/z`. The vector CMPLE/CMPLT/CMPLO/CMPLS are assembler-only swap-
// aliases: the b15:13 values that would render them are instead
// the *wide* encodings (Zm.d) of CMPEQ/…/CMPLT-wide, so this decoder never
// emits a narrow CMPLE/LT/LO/LS. Field layout: Pd [3:0], Zn [9:5], Pg [12:10]
// (3-bit), Zm/imm [20:16], sz [23:22].

extension SVEIntegerDecode {
    // MARK: G7 vector / wide compare + unsigned-immediate compare (0x24)

    @inline(__always)
    static func decodeCompare(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 1 {
            return decodeCompareUnsignedImmediate(e, a, &sink) // sve_int_ucmp_vi
        }
        // sve_int_cmp: (mnemonic, wide) from bits[15:13]; b4 picks the second variant.
        let sel = (e >> 13) & 0b111
        let second = (e >> 4) & 1 == 1
        let (mnemonic, wide) = compareVectorMnemonic(sel, second: second)
        let pd = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        // Wide compares (Zm.d) require the source narrower than .d — sz=.d is UNDEFINED.
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

    /// bits[15:13] × b4 → (mnemonic, isWide) for `sve_int_cmp`. The wide forms
    /// (Zm.d) are the CMP*-wide encodings that occupy the b15:13 slots a narrow
    /// CMPLE/LT/LO/LS would otherwise need; the narrow lt/le/lo/ls are assembler
    /// swap-aliases with no own encoding, so they never appear here.
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
        default: (second ? .cmpls : .cmplo, true) // 0b111
        }
    }

    @inline(__always)
    static func decodeCompareUnsignedImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // sve_int_ucmp_vi: opc = (b13, b4) → hs/hi/lo/ls; imm7 = bits[20:14].
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

    // MARK: G7 signed-immediate compare (0x25, called from decodeImmediate)

    @inline(__always)
    static func decodeCompareSignedImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // sve_int_scmp_vi: opc = (b15:13, b4) → ge/gt/lt/le/eq/ne; imm5 signed = bits[20:16].
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

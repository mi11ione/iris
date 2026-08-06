// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeSVE2Low(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 1 { return decodeSVE2Indexed(e, a, &sink) }
        switch (e >> 10) & 0b111111 {
        case 0b000000, 0b000001: return decodeDotProduct(e, a, &sink)
        case 0b000010, 0b000011: return decodeMultiplyAddLong(e, a, &sink)
        case 0b000100 ... 0b001111: return decodeComplexArith(e, a, &sink)
        case 0b010000 ... 0b011101: return decodeMultiplyAddLong(e, a, &sink)
        case 0b011110: return decodeDotProductMixed(e, a, &sink)
        case 0b100000 ... 0b100111: return decodeSVE2ArithPredicated(e, a, &sink)
        case 0b101000 ... 0b101111:
            return (e >> 20) & 1 == 1 ? decodeSVE2ArithPredicated(e, a, &sink) : decodeUnaryPairwise(e, a, &sink)
        case 0b110000, 0b110001: return decodeClamp(e, a, &sink)
        case 0b110010, 0b110011: return decodeTwoWayDotProduct(e, a, &sink)
        case 0b110100, 0b110110: return decodeCheckedPointerMultiplyAdd(e, a, &sink)
        case 0b110101, 0b110111: return decodeAbsoluteDifferenceAccumulate(e, a, &sink)
        default: return undefined(e, a)
        }
    }

    /// `<mn> <Zdn>.<T>, <Pg>/M, <Zdn>.<T>, <Zm>.<T>`.
    @inline(__always)
    static func decodeSVE2ArithPredicated(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let mnemonic = sve2ArithPredicatedMnemonic((e >> 16) & 0b11111, pairwise: (e >> 13) & 1 == 1)
        else { return undefined(e, a) }
        let dn = zd(e), m = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// opc[20:16] × b13 → mnemonic.
    @inline(__always)
    static func sve2ArithPredicatedMnemonic(_ opc: UInt32, pairwise: Bool) -> Mnemonic? {
        guard !pairwise else {
            return switch opc {
            case 0b10000: .subp
            case 0b10001: .addp
            case 0b10100: .smaxp
            case 0b10101: .umaxp
            case 0b10110: .sminp
            case 0b10111: .uminp
            default: nil
            }
        }
        switch opc {
        case 0b00010: return .srshl
        case 0b00011: return .urshl
        case 0b00110: return .srshlr
        case 0b00111: return .urshlr
        case 0b01000: return .sqshl
        case 0b01001: return .uqshl
        case 0b01010: return .sqrshl
        case 0b01011: return .uqrshl
        case 0b01100: return .sqshlr
        case 0b01101: return .uqshlr
        case 0b01110: return .sqrshlr
        case 0b01111: return .uqrshlr
        case 0b10000: return .shadd
        case 0b10001: return .uhadd
        case 0b10010: return .shsub
        case 0b10011: return .uhsub
        case 0b10100: return .srhadd
        case 0b10101: return .urhadd
        case 0b10110: return .shsubr
        case 0b10111: return .uhsubr
        case 0b11000: return .sqadd
        case 0b11001: return .uqadd
        case 0b11010: return .sqsub
        case 0b11011: return .uqsub
        case 0b11100: return .suqadd
        case 0b11101: return .usqadd
        case 0b11110: return .sqsubr
        case 0b11111: return .uqsubr
        default: return nil
        }
    }

    /// `<mn> <Zda>.<T>, <Zn>.<Tb>, <Zm>.<Tb>`.
    @inline(__always)
    static func decodeDotProduct(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        guard szf != 0 else { return undefined(e, a) }
        return accumulateZZZ(
            e, a, mnemonic: (e >> 10) & 1 == 0 ? .sdot : .udot,
            dest: elementSize(szf), source: szf == 0b11 ? .h : .b, &sink,
        )
    }

    /// `usdot <Zda>.S, <Zn>.B, <Zm>.B`.
    @inline(__always)
    static func decodeDotProductMixed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b10 else { return undefined(e, a) }
        return accumulateZZZ(e, a, mnemonic: .usdot, dest: .s, source: .b, &sink)
    }

    /// bits[15:10] = 11001x holds two different instructions distinguished
    /// only by their size field.
    @inline(__always)
    static func decodeTwoWayDotProduct(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 10) & 1 == 0 ? .sdot : .udot
        switch (e >> 22) & 0b11 {
        case 0b00: return accumulateZZZ(e, a, mnemonic: mnemonic, dest: .s, source: .h, &sink)
        case 0b10:
            let da = zd(e), n = zn(e)
            let m = UInt8((e >> 16) & 0b111), index = UInt8((e >> 19) & 0b11)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(da), category: .sve,
                operandCount: sink.emit(vec(da, .s), vec(n, .h), .scalableVector(ScalableVectorRef(registerIndex: m, element: .h, elementIndex: index))),
                scalableEffect: .readsStreamingMode,
            )
        default: return undefined(e, a)
        }
    }

    @inline(__always)
    static func decodeMultiplyAddLong(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let opc = (e >> 10) & 0b111111
        if opc == 0b011100 || opc == 0b011101 {
            let size = elementSize(szf)
            return accumulateZZZ(e, a, mnemonic: opc == 0b011100 ? .sqrdmlah : .sqrdmlsh, dest: size, source: size, &sink)
        }
        guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
        let mnemonic: Mnemonic
            = switch opc
        {
        case 0b000010: .sqdmlalbt
        case 0b000011: .sqdmlslbt
        case 0b010000: .smlalb
        case 0b010001: .smlalt
        case 0b010010: .umlalb
        case 0b010011: .umlalt
        case 0b010100: .smlslb
        case 0b010101: .smlslt
        case 0b010110: .umlslb
        case 0b010111: .umlslt
        case 0b011000: .sqdmlalb
        case 0b011001: .sqdmlalt
        case 0b011010: .sqdmlslb
        default: .sqdmlslt
        }
        return accumulateZZZ(e, a, mnemonic: mnemonic, dest: elementSize(szf), source: source, &sink)
    }

    @inline(__always)
    static func decodeComplexArith(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let mnemonic: Mnemonic
        let dest = elementSize(szf)
        let source: ScalarSize
        switch (e >> 12) & 0b1111 {
        case 0b0001:
            guard szf >= 0b10, let half = narrower(dest), let quarter = narrower(half) else {
                return undefined(e, a)
            }
            mnemonic = .cdot
            source = quarter
        case 0b0010: mnemonic = .cmla; source = dest
        default: mnemonic = .sqrdcmlah; source = dest
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, source), vec(m, source), .immediate(value: Int64((e >> 10) & 0b11) * 90, width: 16)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeClamp(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), n = zn(e), m = zm(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 10) & 1 == 0 ? .sclamp : .uclamp,
            semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// bits[15:10] = 101xxx with b20 clear holds three classes, separated by
    /// b18 and b17.
    @inline(__always)
    static func decodeUnaryPairwise(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let d = zd(e), n = zn(e), g = pg3(e)
        switch ((e >> 18) & 1, (e >> 17) & 1) {
        case (1, 0):
            guard (e >> 19) & 1 == 0 else { return undefined(e, a) }
            guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e,
                mnemonic: (e >> 16) & 1 == 0 ? .sadalp : .uadalp,
                semanticReads: vecMask(d).union(vecMask(n)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, elementSize(szf)), govern(g, .merging), vec(n, source)),
                scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        case let (0, zeroing):
            let mnemonic: Mnemonic
            switch ((e >> 19) & 1, (e >> 16) & 1) {
            case (0, 0): guard szf == 0b10 else { return undefined(e, a) }; mnemonic = .urecpe
            case (0, 1): guard szf == 0b10 else { return undefined(e, a) }; mnemonic = .ursqrte
            case (1, 0): mnemonic = .sqabs
            default: mnemonic = .sqneg
            }
            let merging = zeroing == 0
            let size = elementSize(szf)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: merging ? vecMask(d).union(vecMask(n)) : vecMask(n),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, size), govern(g, merging ? .merging : .zeroing), vec(n, size)),
                scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
                scalableEffect: merging ? [.readsStreamingMode, .partialWrite] : .readsStreamingMode,
            )
        default: return undefined(e, a)
        }
    }

    @inline(__always)
    static func decodeCheckedPointerMultiplyAdd(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b11 else { return undefined(e, a) }
        let d = zd(e), m = zm(e)
        if (e >> 11) & 1 == 0 {
            return accumulateZZZ(e, a, mnemonic: .mlapt, dest: .d, source: .d, &sink)
        }
        let za = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .madpt,
            semanticReads: vecMask(d).union(vecMask(m)).union(vecMask(za)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, .d), vec(m, .d), vec(za, .d)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `<mn> <Zda>.<dest>, <Zn>.<source>, <Zm>.<source>`.
    @inline(__always)
    static func accumulateZZZ(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, dest: ScalarSize, source: ScalarSize, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, source), vec(m, source)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

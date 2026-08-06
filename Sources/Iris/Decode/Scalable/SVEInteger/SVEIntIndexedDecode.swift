// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    /// The destination width of an indexed form, and the bits its index
    /// occupies.
    enum IndexedWidth {
        case halfword, word, doubleword
    }

    @inline(__always)
    static func decodeSVE2Indexed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 10) & 0b111111 {
        case 0b000000, 0b000001: decodeIndexedDotProduct(e, a, &sink)
        case 0b000110, 0b000111: decodeIndexedDotProductMixed(e, a, &sink)
        case 0b010000 ... 0b011111: decodeIndexedComplexArith(e, a, &sink)
        case 0b110000 ... 0b111111: decodeIndexedMultiply(e, a, &sink)
        default: decodeIndexedMultiplyAdd(e, a, &sink)
        }
    }

    @inline(__always)
    static func decodeIndexedDotProduct(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 10) & 1 == 0 ? .sdot : .udot
        let width = indexedWidth(e)
        let source: ScalarSize = width == .doubleword ? .h : .b
        return indexedDraft(
            e, a, mnemonic: mnemonic, width: width, source: source,
            dest: destElement(width), extraIndexBit: false, &sink,
        )
    }

    /// `usdot`/`sudot <Zda>.S, <Zn>.B, <Zm>.B[<index>]`.
    @inline(__always)
    static func decodeIndexedDotProductMixed(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard indexedWidth(e) == .word else { return undefined(e, a) }
        return indexedDraft(
            e, a, mnemonic: (e >> 10) & 1 == 0 ? .usdot : .sudot,
            width: .word, source: .b, dest: .s, extraIndexBit: false, &sink,
        )
    }

    @inline(__always)
    static func decodeIndexedMultiplyAdd(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let width = indexedWidth(e)
        let dest = destElement(width)
        let top = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic
        let widening: Bool
        switch (e >> 12) & 0b1111 {
        case 0b0000: mnemonic = top ? .mls : .mla; widening = false
        case 0b0001: mnemonic = top ? .sqrdmlsh : .sqrdmlah; widening = false
        case 0b0010: mnemonic = top ? .sqdmlalt : .sqdmlalb; widening = true
        case 0b0011: mnemonic = top ? .sqdmlslt : .sqdmlslb; widening = true
        case 0b1000: mnemonic = top ? .smlalt : .smlalb; widening = true
        case 0b1001: mnemonic = top ? .umlalt : .umlalb; widening = true
        case 0b1010: mnemonic = top ? .smlslt : .smlslb; widening = true
        default: mnemonic = top ? .umlslt : .umlslb; widening = true
        }
        guard let source = indexedSource(dest, widening: widening) else { return undefined(e, a) }
        return indexedDraft(
            e, a, mnemonic: mnemonic, width: width, source: source,
            dest: dest, extraIndexBit: widening, &sink,
        )
    }

    @inline(__always)
    static func decodeIndexedMultiply(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let width = indexedWidth(e)
        let dest = destElement(width)
        let top = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic
        let widening: Bool
        switch (e >> 12) & 0b1111 {
        case 0b1100: mnemonic = top ? .smullt : .smullb; widening = true
        case 0b1101: mnemonic = top ? .umullt : .umullb; widening = true
        case 0b1110: mnemonic = top ? .sqdmullt : .sqdmullb; widening = true
        default:
            widening = false
            switch (e >> 10) & 0b11 {
            case 0b00: mnemonic = .sqdmulh
            case 0b01: mnemonic = .sqrdmulh
            case 0b10: mnemonic = .mul
            default: return undefined(e, a)
            }
        }
        guard let source = indexedSource(dest, widening: widening) else { return undefined(e, a) }
        let d = zd(e), n = zn(e)
        let (m, index) = indexedOperand(e, width: width, extraIndexBit: widening)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, source), .scalableVector(ScalableVectorRef(registerIndex: m, element: source, elementIndex: index))),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeIndexedComplexArith(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 23) & 1 == 1 else { return undefined(e, a) }
        let wide = (e >> 22) & 1 == 1
        let mnemonic: Mnemonic
        let dest: ScalarSize
        let source: ScalarSize
        switch (e >> 12) & 0b1111 {
        case 0b0100: mnemonic = .cdot; dest = wide ? .d : .s; source = wide ? .h : .b
        case 0b0110: mnemonic = .cmla; dest = wide ? .s : .h; source = dest
        case 0b0111: mnemonic = .sqrdcmlah; dest = wide ? .s : .h; source = dest
        default: return undefined(e, a)
        }
        let da = zd(e), n = zn(e)
        let (m, index) = indexedOperand(e, width: wide ? .doubleword : .word, extraIndexBit: false)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, source), .scalableVector(ScalableVectorRef(registerIndex: m, element: source, elementIndex: index)), .immediate(value: Int64((e >> 10) & 0b11) * 90, width: 16)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func indexedWidth(_ e: UInt32) -> IndexedWidth {
        guard (e >> 23) & 1 == 1 else { return .halfword }
        return (e >> 22) & 1 == 1 ? .doubleword : .word
    }

    @inline(__always)
    static func destElement(_ width: IndexedWidth) -> ScalarSize {
        switch width {
        case .halfword: .h
        case .word: .s
        case .doubleword: .d
        }
    }

    /// The source element of an indexed form.
    @inline(__always)
    static func indexedSource(_ dest: ScalarSize, widening: Bool) -> ScalarSize? {
        widening ? (dest == .h ? nil : narrower(dest)) : dest
    }

    /// The `Zm` register and the element index it is subscripted by.
    @inline(__always)
    static func indexedOperand(_ e: UInt32, width: IndexedWidth, extraIndexBit: Bool) -> (m: UInt8, index: UInt8) {
        let m: UInt8
        var index: UInt32
        switch width {
        case .halfword:
            m = UInt8((e >> 16) & 0b111)
            index = ((e >> 20) & 1) << 1 | ((e >> 19) & 1) | ((e >> 22) & 1) << 2
        case .word:
            m = UInt8((e >> 16) & 0b111)
            index = (e >> 19) & 0b11
        case .doubleword:
            m = UInt8((e >> 16) & 0b1111)
            index = (e >> 20) & 1
        }
        if extraIndexBit { index = index << 1 | ((e >> 11) & 1) }
        return (m, UInt8(index))
    }

    /// The common accumulate-into-Zda indexed draft.
    @inline(__always)
    static func indexedDraft(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, width: IndexedWidth,
        source: ScalarSize, dest: ScalarSize, extraIndexBit: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let da = zd(e), n = zn(e)
        let (m, index) = indexedOperand(e, width: width, extraIndexBit: extraIndexBit)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, dest), vec(n, source), .scalableVector(ScalableVectorRef(registerIndex: m, element: source, elementIndex: index))),
            scalableEffect: .readsStreamingMode,
        )
    }
}

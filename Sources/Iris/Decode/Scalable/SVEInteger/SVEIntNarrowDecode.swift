// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeAddSubNarrowHigh(_ e: UInt32, _ a: UInt64, top: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let source = elementSize((e >> 22) & 0b11)
        guard let dest = narrower(source) else { return undefined(e, a) }
        let mnemonic: Mnemonic = switch ((e >> 11) & 0b11, top) {
        case (0b00, false): .addhnb
        case (0b00, true): .addhnt
        case (0b01, false): .raddhnb
        case (0b01, true): .raddhnt
        case (0b10, false): .subhnb
        case (0b10, true): .subhnt
        case (0b11, false): .rsubhnb
        default: .rsubhnt
        }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: narrowReads(dest: d, top: top).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, source), vec(m, source)),
            scalableEffect: narrowEffect(top: top),
        )
    }

    @inline(__always)
    static func decodeSaturatingExtractNarrow(_ e: UInt32, _ a: UInt64, top: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let dest: ScalarSize
        let source: ScalarSize
        switch ((e >> 22) & 1) << 2 | ((e >> 19) & 0b11) {
        case 0b001: (dest, source) = (.b, .h)
        case 0b010: (dest, source) = (.h, .s)
        case 0b100: (dest, source) = (.s, .d)
        default: return undefined(e, a)
        }
        let mnemonic: Mnemonic
        switch ((e >> 11) & 0b11, top) {
        case (0b00, false): mnemonic = .sqxtnb
        case (0b00, true): mnemonic = .sqxtnt
        case (0b01, false): mnemonic = .uqxtnb
        case (0b01, true): mnemonic = .uqxtnt
        case (0b10, false): mnemonic = .sqxtunb
        case (0b10, true): mnemonic = .sqxtunt
        default: return undefined(e, a)
        }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: narrowReads(dest: d, top: top).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, source)),
            scalableEffect: narrowEffect(top: top),
        )
    }

    @inline(__always)
    static func decodeShiftNarrow(_ e: UInt32, _ a: UInt64, top: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (dest, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 1, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let source: ScalarSize = dest == .b ? .h : dest == .h ? .s : .d
        let mnemonic: Mnemonic = switch ((e >> 11) & 0b111, top) {
        case (0b000, false): .sqshrunb
        case (0b000, true): .sqshrunt
        case (0b001, false): .sqrshrunb
        case (0b001, true): .sqrshrunt
        case (0b010, false): .shrnb
        case (0b010, true): .shrnt
        case (0b011, false): .rshrnb
        case (0b011, true): .rshrnt
        case (0b100, false): .sqshrnb
        case (0b100, true): .sqshrnt
        case (0b101, false): .sqrshrnb
        case (0b101, true): .sqrshrnt
        case (0b110, false): .uqshrnb
        case (0b110, true): .uqshrnt
        case (0b111, false): .uqrshrnb
        default: .uqrshrnt
        }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: narrowReads(dest: d, top: top).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, dest), vec(n, source), .immediate(value: 2 * Int64(esize) - Int64(tsz), width: 8)),
            scalableEffect: narrowEffect(top: top),
        )
    }

    /// `<mn> <Zd>.<Tb>, { <Zn>.<T>, <Zn+1>.<T> }`.
    @inline(__always)
    static func decodeMultiVectorExtractNarrow(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 11) & 0b11 {
        case 0b00: mnemonic = .sqcvtn
        case 0b01: mnemonic = .uqcvtn
        case 0b10: mnemonic = .sqcvtun
        default: return undefined(e, a)
        }
        return multiVectorNarrowDraft(e, a, mnemonic: mnemonic, dest: .h, source: .s, shift: nil, &sink)
    }

    @inline(__always)
    static func decodeMultiVectorShiftNarrow(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let (dest, esize, tsz) = decodeTsz(tszHigh: 0, low: (e >> 16) & 0b11111, lowBits: 5)
        else { return undefined(e, a) }
        let source: ScalarSize = dest == .b ? .h : .s
        let mnemonic: Mnemonic
        switch (e >> 11) & 0b111 {
        case 0b000: mnemonic = .sqshrn
        case 0b001: mnemonic = .sqrshrun
        case 0b010: mnemonic = .uqshrn
        case 0b100: mnemonic = .sqshrun
        case 0b101: mnemonic = .sqrshrn
        case 0b111: mnemonic = .uqrshrn
        default: return undefined(e, a)
        }
        return multiVectorNarrowDraft(
            e, a, mnemonic: mnemonic, dest: dest, source: source,
            shift: 2 * Int64(esize) - Int64(tsz), &sink,
        )
    }

    /// Shared draft for the two SVE2p1 multi-vector narrowing forms.
    @inline(__always)
    static func multiVectorNarrowDraft(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic,
        dest: ScalarSize, source: ScalarSize, shift: Int64?, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let d = zd(e)
        let first = UInt8((e >> 6) & 0b1111) << 1
        let group = ScalableVectorGroup(firstIndex: first, count: 2, element: source, layout: .consecutive)
        let operandMark = sink.mark
        _ = sink.emit(vec(d, dest), .scalableVectorGroup(group))
        if let shift { sink.append(.immediate(value: shift, width: 8)) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(group.memberIndex(0)).union(vecMask(group.memberIndex(1))),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.count(since: operandMark),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// A "top" narrowing form writes the odd destination elements and leaves
    /// the even ones untouched, so the destination survives into the result
    /// and is a semantic read; a "bottom" form zeroes them, fully redefining
    /// it.
    @inline(__always)
    static func narrowReads(dest: UInt8, top: Bool) -> RegisterSet {
        top ? vecMask(dest) : .empty
    }

    @inline(__always)
    static func narrowEffect(top: Bool) -> ScalableEffect {
        top ? [.readsStreamingMode, .partialWrite] : .readsStreamingMode
    }
}

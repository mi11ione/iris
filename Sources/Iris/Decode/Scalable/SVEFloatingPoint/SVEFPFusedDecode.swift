// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeFMLAFamily(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let opc = (e >> 13) & 0b11
        let mnemonic: Mnemonic
        var size: ScalarSize = .h
        if sz == 0b00 {
            switch opc {
            case 0b00: mnemonic = .bfmla
            case 0b01: mnemonic = .bfmls
            default: return undefined(e, a)
            }
        } else {
            size = elementSize(sz)
            switch opc {
            case 0b00: mnemonic = .fmla
            case 0b01: mnemonic = .fmls
            case 0b10: mnemonic = .fnmla
            default: mnemonic = .fnmls
            }
        }
        let da = zd(e), n = zn(e), m = zm(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operandCount: sink.emit(vec(da, size), govern(g, .merging), vec(n, size), vec(m, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeFMADFamily(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic = switch (e >> 13) & 0b11 {
        case 0b00: .fmad
        case 0b01: .fmsb
        case 0b10: .fnmad
        default: .fnmsb
        }
        let dn = zd(e), m = zn(e), za = zm(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)).union(vecMask(za)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), govern(g, .merging), vec(m, size), vec(za, size)),
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeFTMAD(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 10) & 0b111 != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let dn = zd(e), m = zn(e)
        let imm3 = UInt64((e >> 16) & 0b111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .ftmad,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(vec(dn, size), vec(dn, size), vec(m, size), .unsignedImmediate(value: imm3, width: 3)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEFloatingPointDecode {
    @inline(__always)
    static func decodeUnpredicated3Op(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let opc = (e >> 10) & 0b111
        let mnemonic: Mnemonic
        var size: ScalarSize = .h
        if sz == 0b00 {
            switch opc {
            case 0b000: mnemonic = .bfadd
            case 0b001: mnemonic = .bfsub
            case 0b010: mnemonic = .bfmul
            default: return undefined(e, a)
            }
        } else {
            size = elementSize(sz)
            switch opc {
            case 0b000: mnemonic = .fadd
            case 0b001: mnemonic = .fsub
            case 0b010: mnemonic = .fmul
            case 0b011: mnemonic = .ftsmul
            case 0b110: mnemonic = .frecps
            case 0b111: mnemonic = .frsqrts
            default: return undefined(e, a)
            }
        }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeReciprocalEstimate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic = (e >> 16) & 1 == 0 ? .frecpe : .frsqrte
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeClamp(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let mnemonic: Mnemonic
        var size: ScalarSize = .h
        if sz == 0b00 {
            mnemonic = .bfclamp
        } else {
            size = elementSize(sz)
            mnemonic = .fclamp
        }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeUnaryTrigCarveOut(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e & 0xFF2E_E000) == 0x040C_A000 {
            return decodeFPAbsNeg(e, a, &sink)
        }
        if (e & 0xFF20_FC00) == 0x0420_B000 {
            return decodeFTSSEL(e, a, &sink)
        }
        return decodeFEXPA(e, a, &sink)
    }

    @inline(__always)
    static func decodeFPAbsNeg(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic = (e >> 16) & 1 == 0 ? .fabs : .fneg
        let merging = (e >> 20) & 1 == 1
        return unaryDraft(
            e, a, mnemonic, size, size,
            merging ? .merging : .zeroing, partial: merging, &sink,
        )
    }

    @inline(__always)
    static func decodeFTSSEL(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let d = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .ftssel,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size), vec(m, size)),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFEXPA(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let d = zd(e), n = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fexpa,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, size), vec(n, size)),
            scalableEffect: .readsStreamingMode,
        )
    }
}

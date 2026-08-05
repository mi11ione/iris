// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the unpredicated forms: G5 three-operand arithmetic
// (`sve_fp_3op_u_zd` — FADD/FSUB/FMUL/FTSMUL/FRECPS/FRSQRTS + B16B16
// BFADD/BFSUB/BFMUL at sz=00), G6 reciprocal estimates (`sve_fp_2op_u_zd` —
// FRECPE/FRSQRTE), G23 clamp (`sve_fp_clamp` — FCLAMP/BFCLAMP, the
// three-source form whose destination carries the value being clamped), and
// the G25 carve-outs at top byte 0x04: FABS/FNEG (merging and the SVE2p2
// zeroing forms) and the trig helpers FTSSEL/FEXPA. All are full writes;
// FCLAMP reads its destination, FABS/FNEG-`/M` reads it through the merging
// predicate.

extension SVEFloatingPointDecode {
    // MARK: G5 — unpredicated 3-op (0x65, bit21=0, bits[15:13]=000)

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

    // MARK: G6 — reciprocal estimates (0x65, bits[15:10]=001100, bits[21:17]=00111)

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

    // MARK: G23 — clamp (0x64, bit21=1, bits[15:10]=001001)

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

    // MARK: G25 — 0x04 carve-outs (FABS/FNEG, FTSSEL, FEXPA)

    @inline(__always)
    static func decodeUnaryTrigCarveOut(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e & 0xFF2E_E000) == 0x040C_A000 {
            return decodeFPAbsNeg(e, a, &sink)
        }
        if (e & 0xFF20_FC00) == 0x0420_B000 {
            return decodeFTSSEL(e, a, &sink)
        }
        return decodeFEXPA(e, a, &sink) // scope guarantees the FEXPA signature here
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e & 0xFF20_4000) == 0x2500_0000 { return decodeCompareSignedImmediate(e, a, &sink) }
        if (e & 0xFF3F_C000) == 0x2538_C000 { return decodeDupImmediate(e, a, &sink) }
        return decodeWideImmediate(e, a, &sink)
    }

    /// The two wide-immediate classes interleave in the opcode space rather
    /// than splitting on a single bit.
    @inline(__always)
    static func decodeWideImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 14) & 1 == 1 else { return undefined(e, a) }
        let mnemonic: Mnemonic
        let signed: Bool
        let hasShift: Bool
        switch (e >> 16) & 0b11111 {
        case 0b00000: (mnemonic, signed, hasShift) = (.add, false, true)
        case 0b00001: (mnemonic, signed, hasShift) = (.sub, false, true)
        case 0b00011: (mnemonic, signed, hasShift) = (.subr, false, true)
        case 0b00100: (mnemonic, signed, hasShift) = (.sqadd, false, true)
        case 0b00101: (mnemonic, signed, hasShift) = (.uqadd, false, true)
        case 0b00110: (mnemonic, signed, hasShift) = (.sqsub, false, true)
        case 0b00111: (mnemonic, signed, hasShift) = (.uqsub, false, true)
        case 0b01000: (mnemonic, signed, hasShift) = (.smax, true, false)
        case 0b01001: (mnemonic, signed, hasShift) = (.umax, false, false)
        case 0b01010: (mnemonic, signed, hasShift) = (.smin, true, false)
        case 0b01011: (mnemonic, signed, hasShift) = (.umin, false, false)
        case 0b10000: (mnemonic, signed, hasShift) = (.mul, true, false)
        default: return undefined(e, a)
        }
        if !hasShift, (e >> 13) & 1 != 0 { return undefined(e, a) }
        return wideImmediateDraft(e, a, mnemonic: mnemonic, signed: signed, hasShift: hasShift, &sink)
    }

    /// Shared wide-immediate destructive draft.
    @inline(__always)
    static func wideImmediateDraft(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, signed: Bool, hasShift: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let dn = zd(e), size = sz(e)
        let raw = (e >> 5) & 0xFF
        if hasShift, (e >> 13) & 1 == 1, size == .b { return undefined(e, a) }
        let shift: UInt32 = hasShift && (e >> 13) & 1 == 1 ? 8 : 0
        let operandMark = sink.mark
        sink.append(vec(dn, size))
        sink.append(vec(dn, size))
        appendShiftedImmediate(raw: raw, shift: shift, signed: signed, to: &sink)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn), semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.count(since: operandMark), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeDupImmediate(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = zd(e), size = sz(e)
        let raw = (e >> 5) & 0xFF
        if (e >> 13) & 1 == 1, size == .b { return undefined(e, a) }
        let shift: UInt32 = (e >> 13) & 1 == 1 ? 8 : 0
        let operandMark = sink.mark
        sink.append(vec(d, size))
        appendShiftedImmediate(raw: raw, shift: shift, signed: true, to: &sink)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .mov,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.count(since: operandMark),
            scalableEffect: .readsStreamingMode,
        )
    }
}

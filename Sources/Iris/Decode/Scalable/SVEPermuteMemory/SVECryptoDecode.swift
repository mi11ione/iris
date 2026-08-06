// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPermuteMemoryDecode {
    /// 0x45 crypto / LUT dispatch.
    @inline(__always)
    static func decodeCrypto(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 13) & 0b111 {
        case 0b111:
            guard (e >> 21) & 0b111 == 0b001 else { return undefined(e, a) }
            return decodeCryptoCore(e, a, &sink)
        default: return decodeLuti(e, a, &sink)
        }
    }

    /// AES/SM4/RAX1/PMULL family, split by bits[15:10].
    @inline(__always)
    static func decodeCryptoCore(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e)
        let hi5 = (e >> 11) & 0x1F
        switch hi5 {
        case 0b11100:
            if (e >> 16) & 0x1F == 0, (e >> 5) & 0x1F == 0 {
                let mn: Mnemonic = (e >> 10) & 1 == 1 ? .aesimc : .aesmc
                return DecodedDraft(
                    address: a, encoding: e, mnemonic: mn,
                    semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
                    operandCount: sink.emit(vec(d, .b), vec(d, .b)),
                    scalableEffect: .readsStreamingMode,
                )
            }
            guard (e >> 17) & 0xF == 0b0001 else { return undefined(e, a) }
            let opc = ((e >> 16) & 1) << 1 | ((e >> 10) & 1)
            let mn: Mnemonic
            let el: ScalarSize
            switch opc {
            case 0b00: mn = .aese; el = .b
            case 0b01: mn = .aesd; el = .b
            case 0b10: mn = .sm4e; el = .s
            default: return undefined(e, a)
            }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(d, el), vec(n, el)),
                scalableEffect: .readsStreamingMode,
            )
        case 0b11110:
            let mn: Mnemonic = (e >> 10) & 1 == 1 ? .rax1 : .sm4ekey
            let el: ScalarSize = mn == .rax1 ? .d : .s
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(n).union(vecMask(m)), semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        case 0b11111:
            guard e & 1 == 0 else { return undefined(e, a) }
            let base = UInt8((e >> 1) & 0xF) &* 2
            let mn: Mnemonic = (e >> 10) & 1 == 1 ? .pmlal : .pmull
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: groupMask(base, count: 2), category: .sve,
                operandCount: sink.emit(group(base, count: 2, .q), vec(n, .d), vec(m, .d)),
                scalableEffect: .readsStreamingMode,
            )
        default:
            return decodeAesMulti(e, a, &sink)
        }
    }

    /// SVE-AES2 multi-vector AES.
    @inline(__always)
    static func decodeAesMulti(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 17) & 0b11 {
        case 0b01, 0b11: break
        default: return undefined(e, a)
        }
        let quad = (e >> 17) & 0b11 == 0b11
        let count: UInt8 = quad ? 4 : 2
        let m = rn(e)
        let imm2 = UInt8((e >> 19) & 0b11)
        let base: UInt8 = quad ? UInt8((e >> 2) & 0b111) &* 4 : UInt8((e >> 1) & 0xF) &* 2
        let mn: Mnemonic
        if quad {
            let opc = ((e >> 16) & 1) << 3 | ((e >> 10) & 1) << 2 | (e & 0b11)
            switch opc {
            case 0b0000: mn = .aese
            case 0b0100: mn = .aesd
            case 0b1000: mn = .aesemc
            case 0b1100: mn = .aesdimc
            default: return undefined(e, a)
            }
        } else {
            let opc = ((e >> 16) & 1) << 2 | ((e >> 10) & 1) << 1 | (e & 1)
            switch opc {
            case 0b000: mn = .aese
            case 0b010: mn = .aesd
            case 0b100: mn = .aesemc
            case 0b110: mn = .aesdimc
            default: return undefined(e, a)
            }
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: groupMask(base, count: count).union(vecMask(m)),
            semanticWrites: groupMask(base, count: count), category: .sve,
            operandCount: sink.emit(group(base, count: count, .b), group(base, count: count, .b), vecIndexed(m, .q, lane: imm2)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// LUTI2 / LUTI4.
    @inline(__always)
    static func decodeLuti(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e)
        let sz = UInt8((e >> 22) & 0b11)
        let mn: Mnemonic, el: ScalarSize, tableRegs: UInt8, index: UInt8?
        switch (e >> 10) & 0x3F {
        case 0b101100: (mn, el, tableRegs, index) = (.luti2, .b, 1, sz)
        case 0b101010: (mn, el, tableRegs, index) = (.luti2, .h, 1, sz &* 2)
        case 0b101110: (mn, el, tableRegs, index) = (.luti2, .h, 1, sz &* 2 &+ 1)
        case 0b101001:
            (mn, el, tableRegs, index) = (.luti4, .b, 1, UInt8((e >> 23) & 1))
        case 0b101111: (mn, el, tableRegs, index) = (.luti4, .h, 1, sz)
        case 0b101101: (mn, el, tableRegs, index) = (.luti4, .h, 2, sz)
        case 0b101011:
            if (e >> 22) & 1 == 1 {
                (mn, el, tableRegs, index) = (.luti6, .h, 2, UInt8((e >> 23) & 1))
            } else if (e >> 23) & 1 == 0 {
                (mn, el, tableRegs, index) = (.luti6, .b, 2, nil)
            } else {
                return undefined(e, a)
            }
        default:
            return undefined(e, a)
        }
        let table = group(n, count: tableRegs, el)
        let zm: Operand = index == nil
            ? vecPlain(m)
            : .scalableVector(ScalableVectorRef(registerIndex: m, elementIndex: index))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: groupMask(n, count: tableRegs).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), table, zm),
            scalableEffect: .readsStreamingMode,
        )
    }
}

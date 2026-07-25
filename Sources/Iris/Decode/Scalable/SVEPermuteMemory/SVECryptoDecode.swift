// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE2 crypto and LUT decoders (top byte 0x45, the cluster
// SVE-integer excludes: bits 21/15/13 set + one of 22/14/12/11). Covers AESE/AESD/
// AESMC/AESIMC, SM4E/SM4EKEY, RAX1, the SVE-AES2 multi-vector AES and the
// 128-bit polynomial PMULL/PMLAL, and LUTI2/LUTI4. Register operands only —
// no memory, no FFR, `flagEffect .none`, `readsStreamingMode` set. AESE/AESD/
// SM4E/AESMC/AESIMC are destructive (Zdn read+written); SM4EKEY/RAX1/PMULL/
// PMLAL/LUTI are constructive.

extension SVEPermuteMemoryDecode {
    /// 0x45 crypto / LUT dispatch. bits[15:13]=111 → AES/SM4/RAX1/PMULL family;
    /// bits[15:13]=101 → LUTI2/LUTI4.
    @inline(__always)
    static func decodeCrypto(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        switch (e >> 13) & 0b111 {
        case 0b111:
            // The AES/SM4/RAX1/PMULL classes fix bits[23:21]=001; other values
            // are holes. (LUTI, below, uses bits[23:22] for its index, so this
            // guard must NOT apply to it.)
            guard (e >> 21) & 0b111 == 0b001 else { return undefined(e, a) }
            return decodeCryptoCore(e, a)
        // The crypto/LUT gate fixes bits 15 and 13, so bits[15:13] is 111 above
        // or 101 here — LUTI2/LUTI4 is all that remains, and the dispatch needs
        // no unreachable UNDEFINED arm.
        default: return decodeLuti(e, a)
        }
    }

    /// AES/SM4/RAX1/PMULL family, split by bits[15:10].
    @inline(__always)
    static func decodeCryptoCore(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e)
        // bits[15:11] classify: 11100 des (AESE/AESD/SM4E), 11100+unary AESMC/
        // AESIMC (bits[20:16]=00000), 11110 SM4EKEY/RAX1, 11101 multi-vector AES,
        // 111110/111111 PMULL/PMLAL multi.
        let hi5 = (e >> 11) & 0x1F
        switch hi5 {
        case 0b11100:
            // Unary AESMC/AESIMC: bits[20:16]=00000, bit10=opc; else des
            // AESE/AESD/SM4E (bit16=opc1, bit10=opc0).
            if (e >> 16) & 0x1F == 0, (e >> 5) & 0x1F == 0 {
                let mn: Mnemonic = (e >> 10) & 1 == 1 ? .aesimc : .aesmc
                return DecodedDraft(
                    address: a, encoding: e, mnemonic: mn,
                    semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
                    operands: [vec(d, .b), vec(d, .b)],
                    scalableEffect: .readsStreamingMode,
                )
            }
            // AESE/AESD/SM4E (`sve2_crypto_des_bin_op`) fix bits[20:17]=0001.
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
                operands: [vec(d, el), vec(d, el), vec(n, el)],
                scalableEffect: .readsStreamingMode,
            )
        case 0b11110:
            // SM4EKEY (bit10=0, .s) / RAX1 (bit10=1, .d) — constructive.
            let mn: Mnemonic = (e >> 10) & 1 == 1 ? .rax1 : .sm4ekey
            let el: ScalarSize = mn == .rax1 ? .d : .s
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(n).union(vecMask(m)), semanticWrites: vecMask(d), category: .sve,
                operands: [vec(d, el), vec(n, el), vec(m, el)],
                scalableEffect: .readsStreamingMode,
            )
        case 0b11111:
            // PMULL (bit10=0) / PMLAL (bit10=1) multi-vector: `{ Zd.q, Zd+1.q },
            // Zn.d, Zm.d`. Zd is 4-bit at bits[4:1] (pair base = field×2); bit0
            // is fixed 0.
            guard e & 1 == 0 else { return undefined(e, a) }
            let base = UInt8((e >> 1) & 0xF) &* 2
            let mn: Mnemonic = (e >> 10) & 1 == 1 ? .pmlal : .pmull
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: groupMask(base, count: 2), category: .sve,
                operands: [group(base, count: 2, .q), vec(n, .d), vec(m, .d)],
                scalableEffect: .readsStreamingMode,
            )
        default:
            // hi5 is bits[15:11]; the dispatch pins bits[15:13]=111, so hi5 is
            // always 111xx and the four arms above are exhaustive — the final
            // arm (0b11101) doubles as the default: SVE-AES2 multi-vector
            // AESE/AESD/AESEMC/AESDIMC (x2 / x4).
            return decodeAesMulti(e, a)
        }
    }

    /// SVE-AES2 multi-vector AES: `sve_crypto_binary_multi2/4`. The group size
    /// (×2 / ×4) is bits[18:17]=01/11; the operation is a 3/4-bit opc; the
    /// indexed key is `Zm.q[imm2]`. Destructive multi-vector groups.
    @inline(__always)
    static func decodeAesMulti(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bits[18:17] fix the group size: 01 → ×2, 11 → ×4; other values are holes.
        switch (e >> 17) & 0b11 {
        case 0b01, 0b11: break
        default: return undefined(e, a)
        }
        let quad = (e >> 17) & 0b11 == 0b11 // 11 → ×4, 01 → ×2
        let count: UInt8 = quad ? 4 : 2
        let m = rn(e) // Zm at bits[9:5]
        let imm2 = UInt8((e >> 19) & 0b11)
        // Zdn group base: ×2 uses bits[4:1] (base×2), ×4 uses bits[4:2] (base×4).
        let base: UInt8 = quad ? UInt8((e >> 2) & 0b111) &* 4 : UInt8((e >> 1) & 0xF) &* 2
        // opc: ×2 = {opc2[16],opc1[10],opc0[0]}; ×4 = {opc3[16],opc2[10],opc1:0[1:0]}.
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
            operands: [
                group(base, count: count, .b),
                group(base, count: count, .b),
                vecIndexed(m, .q, lane: imm2),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    /// LUTI2 / LUTI4 — table lookup with 2-bit / 4-bit indices. `Zd.<T>,
    /// { Zn.<T> }, Zm[index]`. LUTI4 with an H element uses a 2-register table.
    @inline(__always)
    static func decodeLuti(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e)
        let sz = UInt8((e >> 22) & 0b11)
        // The (mnemonic, element, table registers, index) all derive from
        // bits[15:10] (verified against llvm-mc); `sz` = bits[23:22] feeds the
        // index. Zm at bits[20:16] is the plain index vector `z<m>[idx]`.
        let mn: Mnemonic, el: ScalarSize, tableRegs: UInt8, index: UInt8?
        switch (e >> 10) & 0x3F {
        case 0b101100: (mn, el, tableRegs, index) = (.luti2, .b, 1, sz) // b0
        case 0b101010: (mn, el, tableRegs, index) = (.luti2, .h, 1, sz &* 2) // a8
        case 0b101110: (mn, el, tableRegs, index) = (.luti2, .h, 1, sz &* 2 &+ 1) // b8
        case 0b101001: // a4 — luti4 .b, index = bit23 (the scope predicate
            // `isSVE2CryptoOrLUT` requires bit22=1 to reach this class in scope)
            (mn, el, tableRegs, index) = (.luti4, .b, 1, UInt8((e >> 23) & 1))
        case 0b101111: (mn, el, tableRegs, index) = (.luti4, .h, 1, sz) // bc
        case 0b101101: (mn, el, tableRegs, index) = (.luti4, .h, 2, sz) // b4 — 2-reg table
        case 0b101011: // ac — luti6 (2-reg table). bit22=1 → .h (index = bit23);
            // bit22=0 & bit23=0 (sz=00) → .b (no index); sz=10 is a hole.
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
            operands: [vec(d, el), table, zm],
            scalableEffect: .readsStreamingMode,
        )
    }
}

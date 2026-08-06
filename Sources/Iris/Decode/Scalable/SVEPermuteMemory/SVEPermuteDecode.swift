// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPermuteMemoryDecode {
    @inline(__always)
    static func decodePermute(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 13) & 0b111 {
        case 0b000: decodeExt(e, a, &sink)
        case 0b001: decodePermMisc(e, a, &sink)
        case 0b010: decodePredicatePerm(e, a, &sink)
        case 0b011: decodeVectorPerm(e, a, &sink)
        case 0b100: decodePredicatedUnary(e, a, &sink)
        case 0b101: decodeLastToGPR(e, a, &sink)
        default: decodeSel(e, a, &sink)
        }
    }

    /// EXT — `sve_int_perm_extract_i` (destructive, `Zdn,Zdn,Zm,#imm8`) and
    /// `sve2_int_perm_extract_i_cons` (constructive, `Zd,{Zn,Zn+1},#imm8`).
    /// imm8 = bits[20:16]:[12:10]. Constructive has bit23=0,bit22=1.
    @inline(__always)
    static func decodeExt(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 0xF == 0b1101 {
            let mn: Mnemonic
            switch ((e >> 11) & 0b11, (e >> 10) & 1) {
            case (0b00, 0): mn = .zip1
            case (0b00, 1): mn = .zip2
            case (0b01, 0): mn = .uzp1
            case (0b01, 1): mn = .uzp2
            case (0b11, 0): mn = .trn1
            case (0b11, 1): mn = .trn2
            default: return undefined(e, a)
            }
            let d = rd(e), n = rn(e), m = rm(e)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, .q), vec(n, .q), vec(m, .q)),
                scalableEffect: .readsStreamingMode,
            )
        }
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let d = rd(e), m = rn(e)
        let imm8 = Int64(((e >> 16) & 0x1F) << 3 | ((e >> 10) & 0x7))
        let bit22 = (e >> 22) & 1, bit23 = (e >> 23) & 1
        if bit23 == 0, bit22 == 0 {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .ext,
                semanticReads: vecMask(d).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, .b), vec(d, .b), vec(m, .b), .immediate(value: imm8, width: 8)),
                scalableEffect: .readsStreamingMode,
            )
        }
        if bit23 == 0, bit22 == 1 {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .ext,
                semanticReads: groupMask(m, count: 2),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, .b), group(m, count: 2, .b), .immediate(value: imm8, width: 8)),
                scalableEffect: .readsStreamingMode,
            )
        }
        return undefined(e, a)
    }

    /// TBL/TBX/TBXQ, DUPQ/EXTQ, INSR, UNPK, PMOV.
    @inline(__always)
    static func decodePermMisc(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = sz2(e)
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        switch (e >> 10) & 0b111 {
        case 0b001:
            return (e >> 22) & 1 == 1 ? decodeExtq(e, a, &sink) : decodeDupq(e, a, &sink)
        case 0b010:
            return decodeTbl(e, a, sz: sz, &sink)
        case 0b011:
            return decodeTbx(e, a, sz: sz, &sink)
        case 0b100:
            return decodeTbl(e, a, sz: sz, &sink)
        case 0b101:
            return decodeTbx(e, a, sz: sz, &sink)
        case 0b110:
            return decodeInsrUnpkPmov(e, a, sz: sz, &sink)
        default:
            return undefined(e, a)
        }
    }

    /// TBL — `sve_int_perm_tbl<sz,opc>`: `sz · 1 · Zm · 001 · opc[12:11] · 0 ·
    /// Zn · Zd`. opc=10 single-reg `{Zn}`, opc=01 two-reg `{Zn,Zn+1}` (SVE2).
    @inline(__always)
    static func decodeTbl(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz)
        let opc = (e >> 11) & 0b11
        let list: Operand
        let readList: RegisterSet
        switch opc {
        case 0b10: list = group(n, count: 1, el); readList = vecMask(n)
        default: list = group(n, count: 2, el); readList = groupMask(n, count: 2)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .tbl,
            semanticReads: readList.union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), list, vec(m, el)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// TBX / TBXQ.
    @inline(__always)
    static func decodeTbx(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz)
        let opc = (e >> 11) & 0b11
        switch opc {
        case 0b01:
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .tbx,
                semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        default:
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .tbxq,
                semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        }
    }

    /// DUPQ: broadcast an indexed element within each 128-bit segment. Element
    /// size and index derive from the LOWEST set bit of the 5-bit `ind_tsz`
    /// field at bits[20:16].
    @inline(__always)
    static func decodeDupq(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b00 else { return undefined(e, a) }
        let d = rd(e), n = rn(e)
        let tsz = UInt8((e >> 16) & 0x1F)
        guard let (el, index) = quadIndexSize(tsz) else { return undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .dupq,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), vecIndexed(n, el, lane: index)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// EXTQ — `sve2p1_extq`: `Zdn,Zdn,Zm,#imm4` extract within 128-bit
    /// segments. imm4 = bits[19:16].
    @inline(__always)
    static func decodeExtq(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b01 else { return undefined(e, a) }
        guard (e >> 20) & 1 == 0 else { return undefined(e, a) }
        let d = rd(e), m = rn(e)
        let imm4 = Int64((e >> 16) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .extq,
            semanticReads: vecMask(d).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, .b), vec(d, .b), vec(m, .b), .immediate(value: imm4, width: 4)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// INSR (bits[20:16]=00100 GPR / 10100 SIMD), UNPK
    /// (bits[20:16]=1000x/1001x), PMOV (bits[20:16]=01010/01011).
    @inline(__always)
    static func decodeInsrUnpkPmov(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 19) & 0b111 == 0b101 { return decodePmov(e, a, &sink) }
        switch (e >> 16) & 0x1F {
        case 0b00100: return decodeInsr(e, a, sz: sz, fromSIMD: false, &sink)
        case 0b10100: return decodeInsr(e, a, sz: sz, fromSIMD: true, &sink)
        case 0b10000, 0b10001, 0b10010, 0b10011: return decodeUnpk(e, a, sz: sz, &sink)
        case 0b11000: return decodeRevVector(e, a, sz: sz, &sink)
        default: return undefined(e, a)
        }
    }

    /// REV (vector, unpredicated).
    @inline(__always)
    static func decodeRevVector(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), el = esize(sz)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .rev,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), vec(n, el)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// INSR — `sve_int_perm_insrs` (GPR) / `sve_int_perm_insrv` (SIMD&FP).
    /// Destructive: `Zdn.<T>, <R|V>m`.
    @inline(__always)
    static func decodeInsr(_ e: UInt32, _ a: UInt64, sz: UInt8, fromSIMD: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), m = rn(e), el = esize(sz)
        if fromSIMD {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .insr,
                semanticReads: vecMask(d).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), simdScalar(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .insr,
            semanticReads: vecMask(d).union(gprMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), gpr(m, el)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// UNPK — `sve_int_perm_unpk<sz,opc>`: widen half to the next-larger
    /// element. opc bits[17:16]: 00 sunpklo, 01 sunpkhi, 10 uunpklo, 11
    /// uunpkhi. Source element is half the destination (sz gives the
    /// destination H/S/D).
    @inline(__always)
    static func decodeUnpk(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e)
        let destEl = esize(sz)
        guard let src = ScalarSize(rawValue: sz &- 1) else { return undefined(e, a) }
        let mn: Mnemonic = switch (e >> 16) & 0b11 {
        case 0b00: .sunpklo
        case 0b01: .sunpkhi
        case 0b10: .uunpklo
        default: .uunpkhi
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, destEl), vec(n, src)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// PMOV. Direction and element come from the opc composite
    /// (bits[23:22]:[18:17]), with bit16 selecting vector→pred or pred→vector.
    /// Renders `pmov Pd.<T>, Zn` or `pmov Zd, Pn.<T>` with an optional index.
    @inline(__always)
    static func decodePmov(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let toPred = (e >> 16) & 1 == 0
        let d = rd(e), n = rn(e)
        let tszBits: UInt32 = ((e >> 22) & 0b11) << 2 | ((e >> 17) & 0b11)
        let tsz = UInt8(tszBits)
        guard let (el, index) = pmovTsz(tsz) else { return undefined(e, a) }
        if toPred {
            guard (e >> 4) & 1 == 0 else { return undefined(e, a) }
            let zn: Operand = index == nil
                ? vecPlain(n)
                : .scalableVector(ScalableVectorRef(registerIndex: n, elementIndex: index))
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .pmov,
                semanticReads: vecMask(n),
                semanticWrites: .empty, category: .sve,
                operandCount: sink.emit(predElem(d, el, role: .result), zn),
                scalableWrites: predRead(d),
                scalableEffect: .readsStreamingMode,
            )
        }
        guard (e >> 9) & 1 == 0 else { return undefined(e, a) }
        let zd: Operand = index == nil
            ? vecPlain(d)
            : .scalableVector(ScalableVectorRef(registerIndex: d, elementIndex: index))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .pmov,
            semanticReads: .empty,
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(zd, predElem(n, el, role: .governing)),
            scalableReads: predRead(n),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// PMOV element + optional index from the 4-bit tsz composite.
    @inline(__always)
    static func pmovTsz(_ tsz: UInt8) -> (ScalarSize, UInt8?)? {
        if tsz & 0b1000 != 0 { return (.d, tsz & 0b0111) }
        if tsz & 0b0100 != 0 { return (.s, tsz & 0b0011) }
        if tsz & 0b0010 != 0 { return (.h, tsz & 0b0001) }
        if tsz & 0b0001 != 0 { return (.b, nil) }
        return nil
    }

    /// Predicate ZIP/UZP/TRN (`sve_int_perm_bin_perm_pp`, bit20=0), PUNPK
    /// (bit20=1, bits[19:17]=000), REV-pred (bit20=1, bits[19:16]=0100).
    @inline(__always)
    static func decodePredicatePerm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 21) & 1 == 1, (e >> 9) & 1 == 0, (e >> 4) & 1 == 0 else { return undefined(e, a) }
        let sz = sz2(e)
        if (e >> 20) & 1 == 0 {
            let mn: Mnemonic
            switch (e >> 10) & 0b111 {
            case 0b000: mn = .zip1
            case 0b001: mn = .zip2
            case 0b010: mn = .uzp1
            case 0b011: mn = .uzp2
            case 0b100: mn = .trn1
            case 0b101: mn = .trn2
            default: return undefined(e, a)
            }
            let d = pd4(e), n = pn4(e), m = UInt8((e >> 16) & 0xF), el = esize(sz)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mn,
                semanticReads: .empty, semanticWrites: .empty, category: .sve,
                operandCount: sink.emit(predElem(d, el, role: .result), predElem(n, el, role: .governing), predElem(m, el, role: .governing)),
                scalableReads: predRead(n).insertingPredicate(m),
                scalableWrites: predRead(d),
                scalableEffect: .readsStreamingMode,
            )
        }
        guard (e >> 10) & 0b111 == 0 else { return undefined(e, a) }
        if (e >> 16) & 0xF == 0b0100 {
            let d = pd4(e), n = pn4(e), el = esize(sz)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .rev,
                semanticReads: .empty, semanticWrites: .empty, category: .sve,
                operandCount: sink.emit(predElem(d, el, role: .result), predElem(n, el, role: .governing)),
                scalableReads: predRead(n), scalableWrites: predRead(d),
                scalableEffect: .readsStreamingMode,
            )
        }
        guard (e >> 17) & 0b111 == 0 else { return undefined(e, a) }
        guard (e >> 22) & 0b11 == 0 else { return undefined(e, a) }
        let d = pd4(e), n = pn4(e)
        let mn: Mnemonic = (e >> 16) & 1 == 1 ? .punpkhi : .punpklo
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: .empty, semanticWrites: .empty, category: .sve,
            operandCount: sink.emit(predElem(d, .h, role: .result), predElem(n, .b, role: .governing)),
            scalableReads: predRead(n), scalableWrites: predRead(d),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// Vector ZIP/UZP/TRN at opc bits[12:10], rendering `Zd.<T>, Zn.<T>,
    /// Zm.<T>`.
    @inline(__always)
    static func decodeVectorPerm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let mn: Mnemonic
        switch (e >> 10) & 0b111 {
        case 0b000: mn = .zip1
        case 0b001: mn = .zip2
        case 0b010: mn = .uzp1
        case 0b011: mn = .uzp2
        case 0b100: mn = .trn1
        case 0b101: mn = .trn2
        default: return undefined(e, a)
        }
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz2(e))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// COMPACT/EXPAND, SPLICE, CLASTA/B-to-vector, LASTA/B-to-SIMD,
    /// REVB/H/W/D, RBIT.
    @inline(__always)
    static func decodePredicatedUnary(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let sz = sz2(e), field = (e >> 16) & 0x1F
        let d = rd(e), n = rn(e), g = pg3(e), el = esize(sz)
        switch field {
        case 0b00001: return unaryPred(e, a, .compact, d: d, n: n, g: g, el: el, &sink)
        case 0b10001: return unaryPred(e, a, .expand, d: d, n: n, g: g, el: el, &sink)
        case 0b00010: return lastToSIMD(e, a, ab: false, el: el, &sink)
        case 0b00011: return lastToSIMD(e, a, ab: true, el: el, &sink)
        case 0b00100: return revMerging(e, a, .revb, d: d, n: n, g: g, el: el, &sink)
        case 0b00101: return revMerging(e, a, .revh, d: d, n: n, g: g, el: el, &sink)
        case 0b00110: return revMerging(e, a, .revw, d: d, n: n, g: g, el: el, &sink)
        case 0b00111: return revMerging(e, a, .rbit, d: d, n: n, g: g, el: el, &sink)
        case 0b01110: return revMerging(e, a, .revd, d: d, n: n, g: g, el: .q, &sink)
        case 0b01000: return clastToVector(e, a, ab: false, el: el, &sink)
        case 0b01001: return clastToVector(e, a, ab: true, el: el, &sink)
        case 0b01010: return clastToSIMD(e, a, ab: false, el: el, &sink)
        case 0b01011: return clastToSIMD(e, a, ab: true, el: el, &sink)
        case 0b01100:
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .splice,
                semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), govern(g, .none), vec(d, el), vec(n, el)),
                scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
            )
        case 0b01101:
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .splice,
                semanticReads: groupMask(n, count: 2), semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), govern(g, .none), group(n, count: 2, el)),
                scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
            )
        default:
            return undefined(e, a)
        }
    }

    /// COMPACT / EXPAND.
    @inline(__always)
    static func unaryPred(_ e: UInt32, _ a: UInt64, _ mn: Mnemonic, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govern(g, .none), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// Whether a REV*/RBIT size is legal.
    @inline(__always)
    static func revSizeOK(_ mn: Mnemonic, _ sz: UInt8) -> Bool {
        switch mn {
        case .revb: sz >= 1
        case .revh: sz >= 2
        case .revw: sz == 3
        case .revd: sz == 0
        default: true
        }
    }

    /// REVB/REVH/REVW/REVD/RBIT predicated-merging (`/m`).
    @inline(__always)
    static func revMerging(_ e: UInt32, _ a: UInt64, _ mn: Mnemonic, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        guard revSizeOK(mn, sz2(e)) else { return undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govern(g, .merging), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// REVB/REVH/REVW/REVD/RBIT predicated-zeroing (`/z`).
    @inline(__always)
    static func revZeroing(_ e: UInt32, _ a: UInt64, _ mn: Mnemonic, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        guard revSizeOK(mn, sz2(e)) else { return undefined(e, a) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govern(g, .zeroing), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// LASTA/LASTB writing a SIMD&FP scalar.
    @inline(__always)
    static func lastToSIMD(_ e: UInt32, _ a: UInt64, ab: Bool, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: ab ? .lastb : .lasta,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(simdScalar(d, el), govern(g, .none), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// CLASTA/B writing a vector.
    @inline(__always)
    static func clastToVector(_ e: UInt32, _ a: UInt64, ab: Bool, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: ab ? .clastb : .clasta,
            semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govern(g, .none), vec(d, el), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// CLASTA/B writing a SIMD&FP scalar.
    @inline(__always)
    static func clastToSIMD(_ e: UInt32, _ a: UInt64, ab: Bool, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: ab ? .clastb : .clasta,
            semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(simdScalar(d, el), govern(g, .none), simdScalar(d, el), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// The bits[15:13]=101 group.
    @inline(__always)
    static func decodeLastToGPR(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let sz = sz2(e), el = esize(sz)
        let d = rd(e), n = rn(e), g = pg3(e)
        switch (e >> 16) & 0x1F {
        case 0b00000:
            return lastToGPR(e, a, ab: false, d: d, n: n, g: g, el: el, &sink)
        case 0b00001:
            return lastToGPR(e, a, ab: true, d: d, n: n, g: g, el: el, &sink)
        case 0b00100: return revZeroing(e, a, .revb, d: d, n: n, g: g, el: el, &sink)
        case 0b00101: return revZeroing(e, a, .revh, d: d, n: n, g: g, el: el, &sink)
        case 0b00110: return revZeroing(e, a, .revw, d: d, n: n, g: g, el: el, &sink)
        case 0b00111: return revZeroing(e, a, .rbit, d: d, n: n, g: g, el: el, &sink)
        case 0b01110: return revZeroing(e, a, .revd, d: d, n: n, g: g, el: .q, &sink)
        case 0b10000:
            return clastToGPR(e, a, ab: false, d: d, n: n, g: g, el: el, &sink)
        case 0b10001:
            return clastToGPR(e, a, ab: true, d: d, n: n, g: g, el: el, &sink)
        default:
            return undefined(e, a)
        }
    }

    @inline(__always)
    static func lastToGPR(_ e: UInt32, _ a: UInt64, ab: Bool, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: ab ? .lastb : .lasta,
            semanticReads: vecMask(n), semanticWrites: gprMask(d), category: .sve,
            operandCount: sink.emit(gpr(d, el), govern(g, .none), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func clastToGPR(_ e: UInt32, _ a: UInt64, ab: Bool, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: ab ? .clastb : .clasta,
            semanticReads: vecMask(n).union(gprMask(d)), semanticWrites: gprMask(d), category: .sve,
            operandCount: sink.emit(gpr(d, el), govern(g, .none), gpr(d, el), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// SEL — `sve_int_sel_vvv`: `Zd.<T>, Pg, Zn.<T>, Zm.<T>`. Pg is a data
    /// selector (governing, bare, 4-bit at bits[13:10]).
    @inline(__always)
    static func decodeSel(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 21) & 1 == 1, (e >> 14) & 0b11 == 0b11 else { return undefined(e, a) }
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz2(e))
        let g = UInt8((e >> 10) & 0xF)
        let govP = Operand.scalablePredicate(ScalablePredicateRef(registerIndex: g, role: .governing))
        if m == d {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .mov,
                semanticReads: vecMask(d).union(vecMask(n)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), .scalablePredicate(ScalablePredicateRef(registerIndex: g, qualifier: .merging, role: .governing)), vec(n, el)),
                scalableReads: predRead(g), scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .sel,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govP, vec(n, el), vec(m, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// TBLQ/UZPQ1/UZPQ2/ZIPQ1/ZIPQ2 — `sve2p1_permute_vec_elems_q<sz,opc>` at
    /// top byte 0x44: `01000100 · sz · 0 · Zm · 111 · opc[12:10] · Zn · Zd`.
    @inline(__always)
    static func decodeQuadwordPermute(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz2(e))
        let mn: Mnemonic
        switch (e >> 10) & 0b111 {
        case 0b000: mn = .zipq1
        case 0b001: mn = .zipq2
        case 0b010: mn = .uzpq1
        case 0b011: mn = .uzpq2
        case 0b110: mn = .tblq
        default: return undefined(e, a)
        }
        if mn == .tblq {
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .tblq,
                semanticReads: vecMask(n).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), group(n, count: 1, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// Decode the lowest-set-bit `tsz` composite (DUPQ) into (element, index).
    @inline(__always)
    static func quadIndexSize(_ tsz: UInt8) -> (ScalarSize, UInt8)? {
        if tsz & 0b1 == 1 { return (.b, tsz >> 1) }
        if tsz & 0b10 == 0b10 { return (.h, tsz >> 2) }
        if tsz & 0b100 == 0b100 { return (.s, tsz >> 3) }
        if tsz & 0b1000 == 0b1000 { return (.d, tsz >> 4) }
        return nil
    }
}

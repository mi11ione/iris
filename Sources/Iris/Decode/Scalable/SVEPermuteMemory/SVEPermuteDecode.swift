// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE / SVE2 vector-permute decoders (top byte 0x05 and the
// SVE2p1 quadword-permute cluster at 0x44). Dispatch is by bits[15:13] (the
// coarse class column) then refined by bits[12:10]/[20:16]/[23:22], matching
// the LLVM `sve_int_perm_*` / `sve2p1_*` class layouts. Register
// operands only — no memory operand, no FFR. `flagEffect` is always `.none`;
// `readsStreamingMode` is set on every record; `partialWrite` is set only for
// the predicated merging (`/m`) forms.

extension SVEPermuteMemoryDecode {
    // MARK: 0x05 permute dispatch

    @inline(__always)
    static func decodePermute(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        switch (e >> 13) & 0b111 {
        case 0b000: decodeExt(e, a, &sink)
        case 0b001: decodePermMisc(e, a, &sink) // TBL/TBX/DUPQ/EXTQ/INSR/UNPK/PMOV
        case 0b010: decodePredicatePerm(e, a, &sink) // ZIP/UZP/TRN-pred, PUNPK, REV-pred
        case 0b011: decodeVectorPerm(e, a, &sink) // ZIP/UZP/TRN vector (+128-bit)
        case 0b100: decodePredicatedUnary(e, a, &sink) // COMPACT/SPLICE/CLAST-vec/REV*/RBIT/LAST-vec
        case 0b101: decodeLastToGPR(e, a, &sink) // LASTA/B, CLASTA/B to GPR
        // SEL spans bits[15:13] ∈ {110, 111} — bit13 is the high bit of its
        // 4-bit governing predicate, so both values route here.
        default: decodeSel(e, a, &sink)
        }
    }

    // MARK: EXT (bits[15:13]=000)

    /// EXT — `sve_int_perm_extract_i` (destructive, `Zdn,Zdn,Zm,#imm8`) and
    /// `sve2_int_perm_extract_i_cons` (constructive, `Zd,{Zn,Zn+1},#imm8`).
    /// imm8 = bits[20:16]:[12:10]. Constructive has bit23=0,bit22=1.
    @inline(__always)
    static func decodeExt(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // The F64MM 128-bit ZIP/UZP/TRN (`sve_int_perm_bin_perm_128_zz`) share
        // bits[15:13]=000 but fix bits[24:21]=1101 (bit23=1): `Zd.q, Zn.q, Zm.q`,
        // opc bits[12:11] (zip=00, uzp=01, trn=11), P=bit10 selects 1/2.
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
        // EXT fixes bits[23:21]=001 (destructive) / 011 (constructive) — bit21=1.
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let d = rd(e), m = rn(e) // Zm/Zn at bits[9:5]
        let imm8 = Int64(((e >> 16) & 0x1F) << 3 | ((e >> 10) & 0x7))
        let bit22 = (e >> 22) & 1, bit23 = (e >> 23) & 1
        if bit23 == 0, bit22 == 0 {
            // Destructive: `ext Zdn.b, Zdn.b, Zm.b, #imm8`.
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .ext,
                semanticReads: vecMask(d).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, .b), vec(d, .b), vec(m, .b), .immediate(value: imm8, width: 8)),
                scalableEffect: .readsStreamingMode,
            )
        }
        if bit23 == 0, bit22 == 1 {
            // Constructive (SVE2): `ext Zd.b, { Zn.b, Zn+1.b }, #imm8`.
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

    // MARK: misc column (bits[15:13]=001)

    /// TBL/TBX/TBXQ, DUPQ/EXTQ, INSR, UNPK, PMOV — split by bits[12:10].
    @inline(__always)
    static func decodePermMisc(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = sz2(e)
        // The misc column requires bit21=1 (the `1` fixed above bits[20:16] in
        // every one of these classes); bit21=0 words are holes.
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        switch (e >> 10) & 0b111 {
        case 0b001: // DUPQ / EXTQ (SVE2p1), bits[15:10]=001001.
            return (e >> 22) & 1 == 1 ? decodeExtq(e, a, &sink) : decodeDupq(e, a, &sink)
        case 0b010: // TBL two-register (opc=01, bit10=0).
            return decodeTbl(e, a, sz: sz, &sink)
        case 0b011: // TBX (opc=01, bit10=1).
            return decodeTbx(e, a, sz: sz, &sink)
        case 0b100: // TBL single-register (opc=10, bit10=0).
            return decodeTbl(e, a, sz: sz, &sink)
        case 0b101: // TBXQ (opc=10, bit10=1).
            return decodeTbx(e, a, sz: sz, &sink)
        case 0b110: // INSR / UNPK / PMOV — split by bits[20:16].
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
        // opc = bits[12:11] ∈ {01, 10} (the misc-column dispatch pins bit12); the
        // final arm doubles as opc=01 (the two-register SVE2 table).
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

    /// TBX / TBXQ — `sve2_int_perm_tbx<sz,opc>`: bit10=1. opc=01 TBX (`Zd=_Zd`,
    /// destructive), opc=10 TBXQ.
    @inline(__always)
    static func decodeTbx(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz)
        let opc = (e >> 11) & 0b11
        switch opc {
        case 0b01: // TBX — destructive (Zd read+written).
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .tbx,
                semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        // opc ∈ {01, 10} (bit10=1 dispatch); the final arm doubles as opc=10.
        default: // TBXQ (SVE2p1) — destructive within 128-bit segments.
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .tbxq,
                semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), vec(n, el), vec(m, el)),
                scalableEffect: .readsStreamingMode,
            )
        }
    }

    /// DUPQ — `sve2p1_dupq<ind_tsz>`: broadcast an indexed element within each
    /// 128-bit segment. Element size and index derive from the lowest set bit
    /// of the 5-bit `ind_tsz` field at bits[20:16] (B: tsz{0}=1, index above;
    /// H: tsz{1}=1; S: tsz{2}=1; D: tsz{3}=1).
    @inline(__always)
    static func decodeDupq(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b00 else { return undefined(e, a) } // dupq fixes bits[23:22]=00
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

    /// EXTQ — `sve2p1_extq`: `Zdn,Zdn,Zm,#imm4` extract within 128-bit segments.
    /// imm4 = bits[19:16].
    @inline(__always)
    static func decodeExtq(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b01 else { return undefined(e, a) } // extq fixes bits[23:22]=01
        guard (e >> 20) & 1 == 0 else { return undefined(e, a) } // extq fixes bit20=0
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

    /// INSR (bits[20:16]=00100 GPR / 10100 SIMD), UNPK (bits[20:16]=1000x/1001x),
    /// PMOV (bits[20:16]=01010/01011).
    @inline(__always)
    static func decodeInsrUnpkPmov(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        // PMOV (`sve2p1_vector_to_pred`/`_pred_to_vector`) fixes bits[21:19]=101;
        // its element/index ride bits[23:22]:[18:17], so bits[20:16] alone can't
        // distinguish it (the p.d/p.h/p.s forms carry bits[20:16]=01000/01010/
        // 01100). Route it by its fixed field first.
        if (e >> 19) & 0b111 == 0b101 { return decodePmov(e, a, &sink) }
        switch (e >> 16) & 0x1F {
        case 0b00100: return decodeInsr(e, a, sz: sz, fromSIMD: false, &sink)
        case 0b10100: return decodeInsr(e, a, sz: sz, fromSIMD: true, &sink)
        case 0b10000, 0b10001, 0b10010, 0b10011: return decodeUnpk(e, a, sz: sz, &sink)
        case 0b11000: return decodeRevVector(e, a, sz: sz, &sink) // REV vector (unpredicated)
        default: return undefined(e, a)
        }
    }

    /// REV (vector, unpredicated) — `sve_int_perm_reverse_z`: `Zd.<T>, Zn.<T>`.
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

    /// UNPK — `sve_int_perm_unpk<sz,opc>`: widen half to the next-larger element.
    /// opc bits[17:16]: 00 sunpklo, 01 sunpkhi, 10 uunpklo, 11 uunpkhi. Source
    /// element is half the destination (sz gives the destination H/S/D).
    @inline(__always)
    static func decodeUnpk(_ e: UInt32, _ a: UInt64, sz: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let d = rd(e), n = rn(e)
        let destEl = esize(sz)
        // Source element is one size smaller than the destination (H←B, S←H,
        // D←S). A byte destination (sz=00) wraps to an out-of-range source and
        // is rejected below — that nil arm is the sole destination legality gate.
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

    /// PMOV — `sve2p1_vector_to_pred` / `_pred_to_vector`. Direction and element
    /// from the opc composite (bits[23:22]:[18:17]); bit16 (from the field
    /// bits[20:16] low bit) selects vector→pred vs pred→vector. Rendered
    /// `pmov Pd.<T>, Zn` or `pmov Zd, Pn.<T>` (with an optional `[index]`).
    @inline(__always)
    static func decodePmov(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // bit16=0 → vector-to-pred (052a…); bit16=1 → pred-to-vector (052b…).
        let toPred = (e >> 16) & 1 == 0
        let d = rd(e), n = rn(e)
        // Element + optional index from the tsz composite bits[23:22]:[18:17]
        // (the HIGHEST set bit selects the element; the bits below it are the
        // index): 0001→.b (no idx), 001x→.h, 01xx→.s, 1xxx→.d.
        let tszBits: UInt32 = ((e >> 22) & 0b11) << 2 | ((e >> 17) & 0b11)
        let tsz = UInt8(tszBits)
        guard let (el, index) = pmovTsz(tsz) else { return undefined(e, a) }
        if toPred {
            // Pd carries the element suffix (never an index); Zn is a plain
            // vector with the optional index. Pd is 4-bit → bit4 must be 0.
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
        // Pn is 4-bit at bits[8:5] → bit9 must be 0.
        guard (e >> 9) & 1 == 0 else { return undefined(e, a) }
        // Zd is a plain vector with the optional index; Pn carries the element.
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

    /// PMOV element + optional index from the 4-bit tsz composite — the highest
    /// set bit selects the element size, the bits below it form the index.
    @inline(__always)
    static func pmovTsz(_ tsz: UInt8) -> (ScalarSize, UInt8?)? {
        if tsz & 0b1000 != 0 { return (.d, tsz & 0b0111) }
        if tsz & 0b0100 != 0 { return (.s, tsz & 0b0011) }
        if tsz & 0b0010 != 0 { return (.h, tsz & 0b0001) }
        if tsz & 0b0001 != 0 { return (.b, nil) }
        return nil
    }

    // MARK: predicate perms (bits[15:13]=010)

    /// Predicate ZIP/UZP/TRN (`sve_int_perm_bin_perm_pp`, bit20=0), PUNPK
    /// (bit20=1, bits[19:17]=000), REV-pred (bit20=1, bits[19:16]=0100).
    @inline(__always)
    static func decodePredicatePerm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // The predicate-permute classes fix bit21=1 (bits[21:20]=10 bin_perm_pp,
        // 11 punpk/rev) and bit9=0, bit4=0 (the fixed bits around the 4-bit
        // Pn/Pd fields); words that set those are holes.
        guard (e >> 21) & 1 == 1, (e >> 9) & 1 == 0, (e >> 4) & 1 == 0 else { return undefined(e, a) }
        let sz = sz2(e)
        if (e >> 20) & 1 == 0 {
            // bin_perm_pp — opc bits[12:10]; Pm[19:16], Pn[8:5], Pd[3:0].
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
        // bit20=1: PUNPK / REV-pred — both fix bits[12:10]=000 (no opc there);
        // words with bits[12:10]≠000 are holes.
        guard (e >> 10) & 0b111 == 0 else { return undefined(e, a) }
        // REV-pred fixes bits[19:16]=0100; PUNPK fixes bits[19:17]=000 (bit16 =
        // hi/lo). Any other value in bits[19:16] is a hole.
        if (e >> 16) & 0xF == 0b0100 {
            // REV predicate — `sve_int_perm_reverse_p`: rev Pd.<T>, Pn.<T>.
            let d = pd4(e), n = pn4(e), el = esize(sz)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .rev,
                semanticReads: .empty, semanticWrites: .empty, category: .sve,
                operandCount: sink.emit(predElem(d, el, role: .result), predElem(n, el, role: .governing)),
                scalableReads: predRead(n), scalableWrites: predRead(d),
                scalableEffect: .readsStreamingMode,
            )
        }
        guard (e >> 17) & 0b111 == 0 else { return undefined(e, a) } // PUNPK bits[19:17]=000
        // PUNPK is byte-only (`sve_int_perm_punpk` fixes bits[23:22]=00); the
        // rev-pred class above carries a variable size, but PUNPK does not, so
        // words with bits[23:22]≠00 here are holes.
        guard (e >> 22) & 0b11 == 0 else { return undefined(e, a) }
        // PUNPK — bit16 selects hi/lo; dest widened (Pd.H, Pn.B).
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

    // MARK: vector perms (bits[15:13]=011)

    /// Vector ZIP/UZP/TRN — `sve_int_perm_bin_perm_zz<opc,sz>` (opc bits[12:10])
    /// and the F64MM 128-bit `sve_int_perm_bin_perm_128_zz` (bits[15:10]=000,
    /// which does not reach here — it is at bits[23:16]=101_1010 with its own
    /// [15:13]). Here: `Zd.<T>, Zn.<T>, Zm.<T>`.
    @inline(__always)
    static func decodeVectorPerm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // `sve_int_perm_bin_perm_zz` fixes bit21=1.
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

    // MARK: predicated unary/binary cluster (bits[15:13]=100)

    /// COMPACT/EXPAND, SPLICE, CLASTA/B-to-vector, LASTA/B-to-SIMD, REVB/H/W/D,
    /// RBIT — `sve_int_perm_*` with bits[15:13]=100, split by bits[20:16].
    @inline(__always)
    static func decodePredicatedUnary(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // These classes fix bit21=1; bit21=0 words are holes.
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
        case 0b01100: // SPLICE destructive — `Zdn.<T>, Pg, Zdn.<T>, Zm.<T>`.
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .splice,
                semanticReads: vecMask(d).union(vecMask(n)), semanticWrites: vecMask(d), category: .sve,
                operandCount: sink.emit(vec(d, el), govern(g, .none), vec(d, el), vec(n, el)),
                scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
            )
        case 0b01101: // SPLICE constructive (SVE2) — `Zd.<T>, Pg, {Zn,Zn+1}`.
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

    /// COMPACT / EXPAND — `Zd.<T>, Pg, Zn.<T>` (bare governing predicate).
    @inline(__always)
    static func unaryPred(_ e: UInt32, _ a: UInt64, _ mn: Mnemonic, d: UInt8, n: UInt8, g: UInt8, el: ScalarSize, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mn,
            semanticReads: vecMask(n), semanticWrites: vecMask(d), category: .sve,
            operandCount: sink.emit(vec(d, el), govern(g, .none), vec(n, el)),
            scalableReads: predRead(g), scalableEffect: .readsStreamingMode,
        )
    }

    /// Whether a REV*/RBIT size is legal: REVB needs element ≥ H, REVH ≥ S,
    /// REVW = D, REVD = the sz=00 (`.q`) form, RBIT any. (`sz` = bits[23:22].)
    @inline(__always)
    static func revSizeOK(_ mn: Mnemonic, _ sz: UInt8) -> Bool {
        switch mn {
        case .revb: sz >= 1
        case .revh: sz >= 2
        case .revw: sz == 3
        case .revd: sz == 0
        default: true // rbit — all sizes
        }
    }

    /// REVB/REVH/REVW/REVD/RBIT predicated-merging (`/m`) — dest read, partial.
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

    /// REVB/REVH/REVW/REVD/RBIT predicated-zeroing (`/z`) — full write.
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

    /// LASTA/LASTB writing a SIMD&FP scalar — `<V>d, Pg, Zn.<T>`.
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

    /// CLASTA/B writing a vector — destructive `Zdn` conditional extract.
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

    /// CLASTA/B writing a SIMD&FP scalar — `<V>dn, Pg, <V>dn, Zm.<T>`.
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

    // MARK: LAST/CLAST to GPR + REV zeroing (bits[15:13]=101)

    /// The bits[15:13]=101 group: LASTA/LASTB (`last_r`) and CLASTA/CLASTB
    /// (`clast_rz`) writing a GPR, and the REVB/H/W/D/RBIT predicated-zeroing
    /// (`/z`) twins. Split by bits[20:16].
    @inline(__always)
    static func decodeLastToGPR(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // These classes fix bit21=1; bit21=0 words are holes.
        guard (e >> 21) & 1 == 1 else { return undefined(e, a) }
        let sz = sz2(e), el = esize(sz)
        let d = rd(e), n = rn(e), g = pg3(e)
        switch (e >> 16) & 0x1F {
        case 0b00000: // LASTA to GPR — `<R>d, Pg, Zn.<T>`.
            return lastToGPR(e, a, ab: false, d: d, n: n, g: g, el: el, &sink)
        case 0b00001: // LASTB to GPR.
            return lastToGPR(e, a, ab: true, d: d, n: n, g: g, el: el, &sink)
        case 0b00100: return revZeroing(e, a, .revb, d: d, n: n, g: g, el: el, &sink)
        case 0b00101: return revZeroing(e, a, .revh, d: d, n: n, g: g, el: el, &sink)
        case 0b00110: return revZeroing(e, a, .revw, d: d, n: n, g: g, el: el, &sink)
        case 0b00111: return revZeroing(e, a, .rbit, d: d, n: n, g: g, el: el, &sink)
        case 0b01110: return revZeroing(e, a, .revd, d: d, n: n, g: g, el: .q, &sink)
        case 0b10000: // CLASTA to GPR — `<R>dn, Pg, <R>dn, Zm.<T>`.
            return clastToGPR(e, a, ab: false, d: d, n: n, g: g, el: el, &sink)
        case 0b10001: // CLASTB to GPR.
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

    // MARK: SEL (bits[15:13]=110)

    /// SEL — `sve_int_sel_vvv`: `Zd.<T>, Pg, Zn.<T>, Zm.<T>`. Pg is a data
    /// selector (governing, bare, 4-bit at bits[13:10]).
    @inline(__always)
    static func decodeSel(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // SEL — `sve_int_sel_vvv`: bit21=1, bits[15:14]=11 (bit13 is Pg's top).
        guard (e >> 21) & 1 == 1, (e >> 14) & 0b11 == 0b11 else { return undefined(e, a) }
        let d = rd(e), n = rn(e), m = rm(e), el = esize(sz2(e))
        let g = UInt8((e >> 10) & 0xF) // 4-bit governing predicate
        let govP = Operand.scalablePredicate(ScalablePredicateRef(registerIndex: g, role: .governing))
        // SEL with Zm == Zd is the `mov Zd.<T>, Pg/m, Zn.<T>` alias (llvm renders
        // `mov`, merging Zn into the destination under Pg — `sel Zd, Pg, Zn, Zd`).
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

    // MARK: 0x44 quadword permute cluster

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
        // TBLQ uses a single-register table list `{ Zn.<T> }`.
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

    // MARK: helpers

    /// Decode the lowest-set-bit `tsz` composite (DUPQ) into (element, index).
    /// tsz{0}=1 → B; tsz{1}=1 → H; tsz{2}=1 → S; tsz{3}=1 → D; the bits above
    /// the lowest set bit are the segment index.
    @inline(__always)
    static func quadIndexSize(_ tsz: UInt8) -> (ScalarSize, UInt8)? {
        if tsz & 0b1 == 1 { return (.b, tsz >> 1) }
        if tsz & 0b10 == 0b10 { return (.h, tsz >> 2) }
        if tsz & 0b100 == 0b100 { return (.s, tsz >> 3) }
        if tsz & 0b1000 == 0b1000 { return (.d, tsz >> 4) }
        return nil
    }
}

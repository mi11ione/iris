// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SVE2 integer delta at top byte 0x44: the predicated
// saturating/rounding/halving/pairwise arithmetic (the tier's single largest
// class), the multiply-add-long and dot-product accumulate cluster, the
// complex CMLA/CDOT/SQRDCMLAH, SCLAMP/UCLAMP, the predicated saturating
// unaries, the pairwise-accumulate SADALP/UADALP, and the FEAT_CPA
// checked-pointer MADPT/MLAPT. The indexed (b21=1) half lives in
// SVEIntIndexedDecode.swift.
//
// Unlike 0x45, the 0x44 class signatures genuinely overlap — `sve2_int_mla`,
// `sve_intx_dot` and `sve2_complex_int_arith` all merge to value 0x44000000
// and are separated only by which bits their *fixed* sets pin. So the
// sub-dispatch is an explicit (b21, bits[15:10]) tree, derived exhaustively
// from the per-instruction tblgen masks: for each of the 128 signatures the
// set of instruction defs that can satisfy it was computed, and every one
// resolves to a single class (the four residual multi-class signatures are
// separated below by b20 or by the size field, as noted at each site).

extension SVEIntegerDecode {
    @inline(__always)
    static func decodeSVE2Low(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 21) & 1 == 1 { return decodeSVE2Indexed(e, a) }
        switch (e >> 10) & 0b111111 {
        case 0b000000, 0b000001: return decodeDotProduct(e, a) // sve_intx_dot
        case 0b000010, 0b000011: return decodeMultiplyAddLong(e, a) // SQDMLALBT/SQDMLSLBT
        case 0b000100 ... 0b001111: return decodeComplexArith(e, a) // CDOT/CMLA/SQRDCMLAH
        case 0b010000 ... 0b011101: return decodeMultiplyAddLong(e, a) // the long MLA/MLS family
        case 0b011110: return decodeDotProductMixed(e, a) // USDOT
        case 0b100000 ... 0b100111: return decodeSVE2ArithPredicated(e, a) // b13=0 half
        case 0b101000 ... 0b101111:
            // b13=1: `sve2_int_arith_pred`'s pairwise opcodes all set b20; the
            // predicated unary / pairwise-accumulate classes all clear it.
            return (e >> 20) & 1 == 1 ? decodeSVE2ArithPredicated(e, a) : decodeUnaryPairwise(e, a)
        case 0b110000, 0b110001: return decodeClamp(e, a) // SCLAMP/UCLAMP
        case 0b110010, 0b110011: return decodeTwoWayDotProduct(e, a) // sz splits vector vs indexed
        case 0b110100, 0b110110: return decodeCheckedPointerMultiplyAdd(e, a) // MLAPT/MADPT
        case 0b110101, 0b110111: return decodeAbsoluteDifferenceAccumulate(e, a) // SABAL/UABAL
        default: return undefined(e, a) // 011111, and 111xxx (the SVE-permute/memory ZIPQ region, never in scope)
        }
    }

    // MARK: sve2_int_arith_pred — predicated saturating / rounding / halving / pairwise

    /// `<mn> <Zdn>.<T>, <Pg>/M, <Zdn>.<T>, <Zm>.<T>` — destructive merging, so
    /// Zdn is read and only its active lanes are written. Zm sits at
    /// [9:5]; [20:16] is the opcode.
    @inline(__always)
    static func decodeSVE2ArithPredicated(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let mnemonic = sve2ArithPredicatedMnemonic((e >> 16) & 0b11111, pairwise: (e >> 13) & 1 == 1)
        else { return undefined(e, a) }
        let dn = zd(e), m = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// opc[20:16] × b13 → mnemonic. Every form encodes at all four element
    /// sizes; the reserved opcodes (and every b13=1 opcode outside the six
    /// pairwise ones) return nil → UNDEFINED.
    @inline(__always)
    static func sve2ArithPredicatedMnemonic(_ opc: UInt32, pairwise: Bool) -> Mnemonic? {
        guard !pairwise else {
            return switch opc {
            case 0b10000: .subp
            case 0b10001: .addp
            case 0b10100: .smaxp
            case 0b10101: .umaxp
            case 0b10110: .sminp
            case 0b10111: .uminp
            default: nil
            }
        }
        switch opc {
        case 0b00010: return .srshl
        case 0b00011: return .urshl
        case 0b00110: return .srshlr
        case 0b00111: return .urshlr
        case 0b01000: return .sqshl
        case 0b01001: return .uqshl
        case 0b01010: return .sqrshl
        case 0b01011: return .uqrshl
        case 0b01100: return .sqshlr
        case 0b01101: return .uqshlr
        case 0b01110: return .sqrshlr
        case 0b01111: return .uqrshlr
        case 0b10000: return .shadd
        case 0b10001: return .uhadd
        case 0b10010: return .shsub
        case 0b10011: return .uhsub
        case 0b10100: return .srhadd
        case 0b10101: return .urhadd
        case 0b10110: return .shsubr
        case 0b10111: return .uhsubr
        case 0b11000: return .sqadd
        case 0b11001: return .uqadd
        case 0b11010: return .sqsub
        case 0b11011: return .uqsub
        case 0b11100: return .suqadd
        case 0b11101: return .usqadd
        case 0b11110: return .sqsubr
        case 0b11111: return .uqsubr
        default: return nil // 00000, 00001, 00100, 00101
        }
    }

    // MARK: sve_intx_dot — SDOT / UDOT (vector form)

    /// `<mn> <Zda>.<T>, <Zn>.<Tb>, <Zm>.<Tb>` — a four-way (or, at `.h`, two-way)
    /// dot product accumulating into Zda. The source width is not simply one size
    /// down: `.h`/`.s` destinations both read `.b`, and `.d` reads `.h`.
    @inline(__always)
    static func decodeDotProduct(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        guard szf != 0 else { return undefined(e, a) }
        return accumulateZZZ(
            e, a, mnemonic: (e >> 10) & 1 == 0 ? .sdot : .udot,
            dest: elementSize(szf), source: szf == 0b11 ? .h : .b,
        )
    }

    /// `usdot <Zda>.S, <Zn>.B, <Zm>.B` — the mixed-sign dot product (`.s` only).
    @inline(__always)
    static func decodeDotProductMixed(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b10 else { return undefined(e, a) }
        return accumulateZZZ(e, a, mnemonic: .usdot, dest: .s, source: .b)
    }

    /// bits[15:10] = 11001x holds two different instructions distinguished only
    /// by their size field: the two-way vector `sdot`/`udot` (`.s` ← `.h`) at
    /// sz=00, and the SVE2p1 *indexed* two-way dot at sz=10.
    @inline(__always)
    static func decodeTwoWayDotProduct(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let mnemonic: Mnemonic = (e >> 10) & 1 == 0 ? .sdot : .udot
        switch (e >> 22) & 0b11 {
        case 0b00: return accumulateZZZ(e, a, mnemonic: mnemonic, dest: .s, source: .h)
        case 0b10:
            // Indexed: Zm ∈ Z0-Z7 at [18:16], the 2-bit element index at [20:19].
            let da = zd(e), n = zn(e)
            let m = UInt8((e >> 16) & 0b111), index = UInt8((e >> 19) & 0b11)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
                semanticWrites: vecMask(da), category: .sve,
                operands: [
                    vec(da, .s), vec(n, .h),
                    .scalableVector(ScalableVectorRef(registerIndex: m, element: .h, elementIndex: index)),
                ],
                scalableEffect: .readsStreamingMode,
            )
        default: return undefined(e, a)
        }
    }

    // MARK: sve2_int_mla — the multiply-add-long / multiply-subtract-long family

    @inline(__always)
    static func decodeMultiplyAddLong(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let opc = (e >> 10) & 0b111111
        // SQRDMLAH/SQRDMLSH are the two same-width members of this class; every
        // other member widens, so its `.b` destination (sz=00) is reserved.
        if opc == 0b011100 || opc == 0b011101 {
            let size = elementSize(szf)
            return accumulateZZZ(e, a, mnemonic: opc == 0b011100 ? .sqrdmlah : .sqrdmlsh, dest: size, source: size)
        }
        guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
        let mnemonic: Mnemonic
            // The dispatch routes only 000010/000011 and 010000-011101 here, and
            // the two same-width opcodes returned above, so this switch's domain
            // is exactly the fourteen widening members.
            = switch opc
        {
        case 0b000010: .sqdmlalbt
        case 0b000011: .sqdmlslbt
        case 0b010000: .smlalb
        case 0b010001: .smlalt
        case 0b010010: .umlalb
        case 0b010011: .umlalt
        case 0b010100: .smlslb
        case 0b010101: .smlslt
        case 0b010110: .umlslb
        case 0b010111: .umlslt
        case 0b011000: .sqdmlalb
        case 0b011001: .sqdmlalt
        case 0b011010: .sqdmlslb
        default: .sqdmlslt // 0b011011
        }
        return accumulateZZZ(e, a, mnemonic: mnemonic, dest: elementSize(szf), source: source)
    }

    // MARK: sve2_complex_int_arith — CDOT / CMLA / SQRDCMLAH (rotation immediate)

    @inline(__always)
    static func decodeComplexArith(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let mnemonic: Mnemonic
        let dest = elementSize(szf)
        let source: ScalarSize
        // The dispatch routes only 000100-001111 here, so bits[15:12] span
        // exactly the three allocated values.
        switch (e >> 12) & 0b1111 {
        case 0b0001: // CDOT — a four-way complex dot product, so the source is *two* sizes down.
            guard szf >= 0b10, let half = narrower(dest), let quarter = narrower(half) else {
                return undefined(e, a)
            }
            mnemonic = .cdot
            source = quarter
        case 0b0010: mnemonic = .cmla; source = dest
        default: mnemonic = .sqrdcmlah; source = dest // 0b0011
        }
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [
                vec(da, dest), vec(n, source), vec(m, source),
                .immediate(value: Int64((e >> 10) & 0b11) * 90, width: 16),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_clamp — SCLAMP / UCLAMP

    @inline(__always)
    static func decodeClamp(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // Three-source: Zd carries the value being clamped, Zn/Zm the bounds. The
        // ASL reads Zd as a plain operand and then recomputes every lane, so it is
        // a destination read with a *full* write.
        let d = zd(e), n = zn(e), m = zm(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: (e >> 10) & 1 == 0 ? .sclamp : .uclamp,
            semanticReads: vecMask(d).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), vec(n, size), vec(m, size)],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: sve2_int_un_pred_arit(_z) + sve2_int_sadd_long_accum_pairwise

    /// bits[15:10] = 101xxx with b20 clear holds three classes, separated by
    /// b18/b17: the predicated saturating unaries in their merging (b18=0,b17=0)
    /// and zeroing (b18=0,b17=1) forms, and the pairwise-accumulate SADALP/UADALP
    /// (b18=1,b17=0).
    @inline(__always)
    static func decodeUnaryPairwise(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let szf = (e >> 22) & 0b11
        let d = zd(e), n = zn(e), g = pg3(e)
        switch ((e >> 18) & 1, (e >> 17) & 1) {
        case (1, 0): // SADALP / UADALP — widening pairwise accumulate, always /M
            // Their opcodes are 00100/00101, so b19 must be clear; b19=1 is reserved.
            guard (e >> 19) & 1 == 0 else { return undefined(e, a) }
            guard szf != 0, let source = narrower(elementSize(szf)) else { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e,
                mnemonic: (e >> 16) & 1 == 0 ? .sadalp : .uadalp,
                semanticReads: vecMask(d).union(vecMask(n)),
                semanticWrites: vecMask(d), category: .sve,
                operands: [vec(d, elementSize(szf)), govern(g, .merging), vec(n, source)],
                scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        case let (0, zeroing): // SQABS/SQNEG (any size) and URECPE/URSQRTE (.s only)
            let mnemonic: Mnemonic
            switch ((e >> 19) & 1, (e >> 16) & 1) {
            case (0, 0): guard szf == 0b10 else { return undefined(e, a) }; mnemonic = .urecpe
            case (0, 1): guard szf == 0b10 else { return undefined(e, a) }; mnemonic = .ursqrte
            case (1, 0): mnemonic = .sqabs
            default: mnemonic = .sqneg
            }
            let merging = zeroing == 0
            let size = elementSize(szf)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: merging ? vecMask(d).union(vecMask(n)) : vecMask(n),
                semanticWrites: vecMask(d), category: .sve,
                operands: [vec(d, size), govern(g, merging ? .merging : .zeroing), vec(n, size)],
                scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
                scalableEffect: merging ? [.readsStreamingMode, .partialWrite] : .readsStreamingMode,
            )
        default: return undefined(e, a) // b18=1, b17=1
        }
    }

    // MARK: sve_int_mla_cpa / sve_int_mad_cpa — FEAT_CPA checked-pointer multiply-add

    @inline(__always)
    static func decodeCheckedPointerMultiplyAdd(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard (e >> 22) & 0b11 == 0b11 else { return undefined(e, a) } // `.d` only
        let d = zd(e), m = zm(e)
        if (e >> 11) & 1 == 0 { // MLAPT — `<Zda>.D, <Zn>.D, <Zm>.D`
            return accumulateZZZ(e, a, mnemonic: .mlapt, dest: .d, source: .d)
        }
        // MADPT — `<Zdn>.D, <Zm>.D, <Za>.D`: the multiplicand is Zdn, the addend Za at [9:5].
        let za = zn(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .madpt,
            semanticReads: vecMask(d).union(vecMask(m)).union(vecMask(za)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, .d), vec(m, .d), vec(za, .d)],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: shared

    /// `<mn> <Zda>.<dest>, <Zn>.<source>, <Zm>.<source>` — an accumulate form:
    /// Zda is read and every output lane recomputed, so the write is full.
    @inline(__always)
    static func accumulateZZZ(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, dest: ScalarSize, source: ScalarSize,
    ) -> DecodedDraft {
        let da = zd(e), n = zn(e), m = zm(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [vec(da, dest), vec(n, source), vec(m, source)],
            scalableEffect: .readsStreamingMode,
        )
    }
}

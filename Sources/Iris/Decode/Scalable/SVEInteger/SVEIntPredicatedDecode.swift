/// Copyright (c) 2026 Roman Zhuzhgov
/// Licensed under the Apache License, Version 2.0
///
/// the predicated SVE integer groups: G1 (arith/logical), G2
/// (shifts by register, by wide elements, and by immediate), G3 (unary), G4
/// (multiply-add), G5 (reductions, including the SVE2p1 quadword forms). All
/// share the predicated field layout — Zd/Zdn/Zda at [4:0], Zn/Zm at [9:5], Pg
/// at [12:10], sz at [23:22] — but each group reads its operation selector from
/// a different place: [20:16] for G1 and G5, [19:16] for G3 and the G2
/// immediate, [15:14]+[13] for G4.
///
/// Per the predicated `/M` destructive forms read their destination
/// (RMW) and set `partialWrite` (inactive lanes preserve it); `/Z` forms are
/// full writes; reductions write a scalar SIMD register (or, for the quadword
/// forms, a whole NEON vector). Every in-scope form sets `readsStreamingMode`
///
extension SVEIntegerDecode {
    // MARK: G1 — predicated integer arith / logical (destructive /M)

    @inline(__always)
    static func decodePredicatedArithLog(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let mnemonic = predicatedArithLogMnemonic((e >> 16) & 0b11111, sz: (e >> 22) & 0b11) else {
            return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        // `add Zdn.T, Pg/m, Zdn.T, Zm.T` — destructive: Zdn (=Zd, low field) is
        // the accumulator and the second source; Zm is at [9:5].
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d).union(vecMask(n)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [
                vec(d, size), govern(g, .merging), vec(d, size), vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    /// opc[20:16] × sz → mnemonic for `sve_int_bin_pred_arit_log`. SDIV/UDIV/
    /// SDIVR/UDIVR are legal only for sz ∈ {S, D}; every other opc is size-
    /// independent. Returns nil for reserved opc / illegal size (→ UNDEFINED).
    @inline(__always)
    static func predicatedArithLogMnemonic(_ opc: UInt32, sz: UInt32) -> Mnemonic? {
        switch opc {
        case 0x00: .add
        case 0x01: .sub
        case 0x03: .subr
        case 0x04: sz == 0b11 ? .addpt : nil // FEAT_CPA, .d only
        case 0x05: sz == 0b11 ? .subpt : nil
        case 0x08: .smax
        case 0x09: .umax
        case 0x0A: .smin
        case 0x0B: .umin
        case 0x0C: .sabd
        case 0x0D: .uabd
        case 0x10: .mul
        case 0x12: .smulh
        case 0x13: .umulh
        case 0x14: sz == 0b10 || sz == 0b11 ? .sdiv : nil
        case 0x15: sz == 0b10 || sz == 0b11 ? .udiv : nil
        case 0x16: sz == 0b10 || sz == 0b11 ? .sdivr : nil
        case 0x17: sz == 0b10 || sz == 0b11 ? .udivr : nil
        case 0x18: .orr
        case 0x19: .eor
        case 0x1A: .and
        case 0x1B: .bic
        default: nil
        }
    }

    // MARK: G3 — predicated unary (/M or /Z)

    @inline(__always)
    static func decodePredicatedUnary(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let merging = (e >> 20) & 1 == 1 // b20: 1 = /M (sve_int_un_pred_arit), 0 = /Z (…_z, SVE2p2)
        guard let mnemonic = predicatedUnaryMnemonic((e >> 16) & 0b1111, sz: (e >> 22) & 0b11) else {
            return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        var reads = vecMask(n)
        var effect: ScalableEffect = .readsStreamingMode
        if merging {
            reads = reads.union(vecMask(d)) // /M merges inactive lanes → Zd is RMW
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: vecMask(d), category: .sve,
            operands: [
                vec(d, size), govern(g, merging ? .merging : .zeroing), vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: effect,
        )
    }

    /// opc[19:16] × sz → mnemonic for the predicated unary family. The sign/
    /// zero-extend ops are size-gated (SXTB/UXTB need sz ≥ H, SXTH/UXTH ≥ S,
    /// SXTW/UXTW = D). FABS/FNEG (opc 0b1100/0b1101 with b19=1) are excluded by
    /// the scope predicate. Returns nil for reserved opc / illegal size.
    @inline(__always)
    static func predicatedUnaryMnemonic(_ opc: UInt32, sz: UInt32) -> Mnemonic? {
        switch opc {
        case 0x0: sz >= 0b01 ? .sxtb : nil
        case 0x1: sz >= 0b01 ? .uxtb : nil
        case 0x2: sz >= 0b10 ? .sxth : nil
        case 0x3: sz >= 0b10 ? .uxth : nil
        case 0x4: sz == 0b11 ? .sxtw : nil
        case 0x5: sz == 0b11 ? .uxtw : nil
        case 0x6: .abs
        case 0x7: .neg
        case 0x8: .cls
        case 0x9: .clz
        case 0xA: .cnt
        case 0xB: .cnot
        case 0xE: .not
        default: nil
        }
    }

    // MARK: G4 — predicated multiply-add (MLA/MLS accumulate; MAD/MSB multiply)

    @inline(__always)
    static func decodeMultiplyAddMLA(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // `mla Zda.T, Pg/m, Zn.T, Zm.T` — Zda [4:0] accumulate, Zn [9:5], Zm [20:16].
        let da = zd(e), n = zn(e), m = zm(e), g = pg3(e), size = sz(e)
        let mnemonic: Mnemonic = (e >> 13) & 1 == 0 ? .mla : .mls
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [vec(da, size), govern(g, .merging), vec(n, size), vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodeMultiplyAddMAD(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // `mad Zdn.T, Pg/m, Zm.T, Za.T` — Zdn [4:0] multiplicand, Zm [20:16], Za [9:5].
        let dn = zd(e), m = zm(e), za = zn(e), g = pg3(e), size = sz(e)
        let mnemonic: Mnemonic = (e >> 13) & 1 == 0 ? .mad : .msb
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn).union(vecMask(m)).union(vecMask(za)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [vec(dn, size), govern(g, .merging), vec(m, size), vec(za, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: G5 — reductions (write a scalar SIMD register; SVE2p1 quadword → NEON vector)

    @inline(__always)
    static func decodeReduction(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // sve_int_reduce and sve2p1_int_reduce_q share b15:13=001, and b18 is the
        // bit that separates them: every scalar-reduction opcode clears it, every
        // quadword-reduction opcode sets it.
        if (e >> 18) & 1 == 1 {
            return decodeReductionQuadword(e, a)
        }
        guard let mnemonic = reductionMnemonic((e >> 16) & 0b11111) else { return undefined(e, a) }
        let vd = zd(e), n = zn(e), g = pg3(e), size = sz(e)
        // SADDV sign-extends its elements into a 64-bit accumulator, which a `.d`
        // source has nothing to widen into — so `.d` is reserved for SADDV alone.
        // UADDV encodes at every size (a `.d` UADDV is a plain 64-bit sum).
        if mnemonic == .saddv, size == .d { return undefined(e, a) }
        // SADDV/UADDV always write a D scalar; the others write a scalar of the
        // element width. The destination is a SIMD register (bit 32+d).
        let destSize: ScalarSize = mnemonic == .saddv || mnemonic == .uaddv ? .d : size
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(vd), category: .sve,
            operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: vd, view: .scalar(size: destSize))),
                govern(g, .none), vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// opc[20:16] → mnemonic for `sve_int_reduce`. Every reduction encodes at
    /// every element size; the sole size asymmetry is SADDV's reserved `.d`
    /// (handled by the caller), so this table gates on the opcode alone.
    @inline(__always)
    static func reductionMnemonic(_ opc: UInt32) -> Mnemonic? {
        switch opc {
        case 0x00: .saddv
        case 0x01: .uaddv
        case 0x08: .smaxv
        case 0x09: .umaxv
        case 0x0A: .sminv
        case 0x0B: .uminv
        case 0x18: .orv
        case 0x19: .eorv
        case 0x1A: .andv
        default: nil
        }
    }

    // MARK: G5 — SVE2p1 quadword reductions (write a full NEON vector, not a scalar)

    /// `<mn> <Vd>.<arr>, <Pg>, <Zn>.<T>` — reduces each 128-bit segment of Zn to
    /// one element, so the result is a whole NEON vector whose arrangement is the
    /// element size packed into 128 bits (`.b` → `v0.16b`, `.d` → `v0.2d`).
    @inline(__always)
    static func decodeReductionQuadword(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b11111 {
        case 0b00101: mnemonic = .addqv
        case 0b01100: mnemonic = .smaxqv
        case 0b01101: mnemonic = .umaxqv
        case 0b01110: mnemonic = .sminqv
        case 0b01111: mnemonic = .uminqv
        case 0b11100: mnemonic = .orqv
        case 0b11101: mnemonic = .eorqv
        case 0b11110: mnemonic = .andqv
        default: return undefined(e, a)
        }
        let size = sz(e)
        let arrangement: VectorArrangement = switch size {
        case .b: .b16
        case .h: .h8
        case .s: .s4
        default: .d2 // .d (`.q` cannot be encoded by the 2-bit size field)
        }
        let vd = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n), semanticWrites: vecMask(vd), category: .sve,
            operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: vd, view: .full(arrangement: arrangement))),
                govern(g, .none), vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G2 — predicated shifts (register, wide, and immediate with tsz)

    @inline(__always)
    static func decodePredicatedShift(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 20) & 1 == 0 { return decodePredicatedShiftImmediate(e, a) } // sve_int_bin_pred_shift_imm
        if (e >> 19) & 1 == 1 { return decodePredicatedShiftWide(e, a) } // wide (Zm.D)
        // Register shift `<mn> Zdn.T, Pg/m, Zdn.T, Zm.T` — opc[18:16].
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .asr
        case 0b001: mnemonic = .lsr
        case 0b011: mnemonic = .lsl
        case 0b100: mnemonic = .asrr
        case 0b101: mnemonic = .lsrr
        case 0b111: mnemonic = .lslr
        default: return undefined(e, a)
        }
        return predicatedShiftRegisterDraft(e, a, mnemonic: mnemonic, wide: false)
    }

    @inline(__always)
    static func decodePredicatedShiftWide(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if sz(e) == .d { return undefined(e, a) } // wide requires source < .d
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .asr
        case 0b001: mnemonic = .lsr
        case 0b011: mnemonic = .lsl
        default: return undefined(e, a)
        }
        return predicatedShiftRegisterDraft(e, a, mnemonic: mnemonic, wide: true)
    }

    /// Shared predicated register/wide shift draft: `Zdn.T, Pg/m, Zdn.T, Zm.<T|d>`.
    @inline(__always)
    static func predicatedShiftRegisterDraft(_ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, wide: Bool) -> DecodedDraft {
        let d = zd(e), m = zn(e), g = pg3(e), size = sz(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d).union(vecMask(m)),
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), govern(g, .merging), vec(d, size), vec(m, wide ? .d : size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    @inline(__always)
    static func decodePredicatedShiftImmediate(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // opc[18:16] + b19 select the operation; the element and amount come
        // from the tsz field (tszh [23:22], tszl:imm3 [9:5]).
        let selector = (((e >> 19) & 1) << 3) | ((e >> 16) & 0b111)
        let (mnemonic, isLeft): (Mnemonic, Bool)
        switch selector {
        case 0b0000: (mnemonic, isLeft) = (.asr, false)
        case 0b0001: (mnemonic, isLeft) = (.lsr, false)
        case 0b0011: (mnemonic, isLeft) = (.lsl, true)
        case 0b0100: (mnemonic, isLeft) = (.asrd, false)
        case 0b0110: (mnemonic, isLeft) = (.sqshl, true)
        case 0b0111: (mnemonic, isLeft) = (.uqshl, true)
        case 0b1100: (mnemonic, isLeft) = (.srshr, false)
        case 0b1101: (mnemonic, isLeft) = (.urshr, false)
        case 0b1111: (mnemonic, isLeft) = (.sqshlu, true)
        default: return undefined(e, a)
        }
        guard let (element, esize, tsz) = decodeTsz(tszHigh: (e >> 22) & 0b11, low: (e >> 5) & 0b11111, lowBits: 5) else {
            return undefined(e, a)
        }
        let amount = isLeft ? Int64(tsz) - Int64(esize) : 2 * Int64(esize) - Int64(tsz)
        let d = zd(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(d), semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, element), govern(g, .merging), vec(d, element), .immediate(value: amount, width: 8)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}

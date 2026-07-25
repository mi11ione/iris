// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FP reductions: G7 fast recursive reductions
// (`sve_fp_fast_red` — FADDV/FMAXNMV/FMINNMV/FMAXV/FMINV, scalar destination
// of the element width), G8 the strictly-ordered sequential FADDA
// (`sve_fp_2op_p_vd` — scalar accumulator read and written, appearing twice
// in the operand list), and G24 the SVE2p1 quadword reductions
// (`sve2p1_fp_reduction_q` — NEON-vector destination `Vd.8h/4s/2d`). The
// reduction destination is a SIMD write at the shared Z/V canonical bit
// 32+d; the governing predicate is bare (no qualifier). All are full writes.

extension SVEFloatingPointDecode {
    // MARK: G7 — fast reductions (0x65, bits[20:19]=00, bits[15:12]=0010)

    @inline(__always)
    static func decodeFastReduction(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bit19 is a fixed zero field; the reduction-column dispatch only routes
        // here when bits[20:19]==00, so it is always zero and needs no re-check.
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .faddv
        case 0b100: mnemonic = .fmaxnmv
        case 0b101: mnemonic = .fminnmv
        case 0b110: mnemonic = .fmaxv
        case 0b111: mnemonic = .fminv
        default: return undefined(e, a)
        }
        let d = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: d, view: .scalar(size: size))),
                govern(g, .none),
                vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G8 — FADDA (0x65, bits[20:19]=11, bits[15:12]=0010)

    @inline(__always)
    static func decodeFADDA(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bits[18:16] are a fixed zero field (FADDA is the region's only form).
        if (e >> 16) & 0b111 != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let dn = zd(e), m = zn(e), g = pg3(e)
        let scalar = Operand.vectorRegister(
            VectorRegisterRef(registerIndex: dn, view: .scalar(size: size)),
        )
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fadda,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [scalar, govern(g, .none), scalar, vec(m, size)],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G24 — quadword reductions (0x64, bits[20:19]=10, bits[15:13]=101)

    @inline(__always)
    static func decodeQuadReduction(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // The class pins bits[15:13]=101; the dispatcher's else-branch also
        // carries the 110/111 holes here, so bits[14:13] must be re-checked.
        if (e >> 13) & 0b11 != 0b01 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let mnemonic: Mnemonic
        switch (e >> 16) & 0b111 {
        case 0b000: mnemonic = .faddqv
        case 0b100: mnemonic = .fmaxnmqv
        case 0b101: mnemonic = .fminnmqv
        case 0b110: mnemonic = .fmaxqv
        case 0b111: mnemonic = .fminqv
        default: return undefined(e, a)
        }
        let arrangement: VectorArrangement = switch size {
        case .h: .h8
        case .s: .s4
        default: .d2
        }
        let d = zd(e), n = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(n),
            semanticWrites: vecMask(d), category: .sve,
            operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: d, view: .full(arrangement: arrangement))),
                govern(g, .none),
                vec(n, size),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: .readsStreamingMode,
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// G26, the FP move immediates: FDUP (`sve_int_dup_fpimm`,
// top byte 0x25) and FCPY (`sve_int_dup_fpimm_pred`, top byte 0x05). Both
// always disassemble as their `fmov` alias (the family's only Emit≥1
// aliases), so the decoder emits `.fmov` directly — no `.fdup`/`.fcpy`
// tokens exist, mirroring SVE-integer's DUP/CPY→`mov` convention. The 8-bit
// immediate expands through the `vfpExpandImm` to the IEEE bit pattern
// at the element precision (never zero — `fmov …, #0.0` assembles to SVE-integer's
// integer DUP). FCPY is merging: destination read + `partialWrite`.

extension SVEFloatingPointDecode {
    // MARK: FDUP → fmov (0x25)

    @inline(__always)
    static func decodeFDup(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let kind = immediateKind(size)
        let bits = vfpExpandImm(imm8: UInt8((e >> 5) & 0xFF), kind: kind)
        let d = zd(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fmov,
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), .floatImmediate(bits: bits, kind: kind)],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: FCPY → fmov (0x05)

    @inline(__always)
    static func decodeFCopy(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let kind = immediateKind(size)
        let bits = vfpExpandImm(imm8: UInt8((e >> 5) & 0xFF), kind: kind)
        let d = zd(e)
        let g = UInt8((e >> 16) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fmov,
            semanticReads: vecMask(d),
            semanticWrites: vecMask(d), category: .sve,
            operands: [
                vec(d, size),
                govern(g, .merging),
                .floatImmediate(bits: bits, kind: kind),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }
}

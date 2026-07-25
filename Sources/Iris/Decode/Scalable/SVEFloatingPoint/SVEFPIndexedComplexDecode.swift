// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// complex FP and the indexed multiply forms: G17 FCADD
// (predicated destructive, rotation #90/#270), FCMLA vector (predicated
// accumulator, rotation #0/#90/#180/#270), FCMLA indexed (unpredicated
// accumulator; H uses a 2-bit index with a 3-bit Zm, S a 1-bit index with a
// 4-bit Zm), and G18 the indexed FMLA/FMLS/FMUL family (per-size index
// packing: H takes bits[22,20,19], S bits[20:19], D bit[20]; the bf16 twins
// share the H space selected by the low opcode bits). Indexed accumulators
// read their destination but rewrite every lane (`partialWrite` clear);
// the predicated complex forms are merging.

extension SVEFloatingPointDecode {
    // MARK: G17 — FCADD (0x64, bit21=0, bits[20:16]=0000x, bits[15:13]=100)

    @inline(__always)
    static func decodeFCADD(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // bits[20:17] are a fixed zero field; bit16 is the rotation.
        if (e >> 17) & 0xF != 0 { return undefined(e, a) }
        guard let size = fpSize(e) else { return undefined(e, a) }
        let rotation: Int64 = (e >> 16) & 1 == 0 ? 90 : 270
        let dn = zd(e), m = zn(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcadd,
            semanticReads: vecMask(dn).union(vecMask(m)),
            semanticWrites: vecMask(dn), category: .sve,
            operands: [
                vec(dn, size), govern(g, .merging), vec(dn, size), vec(m, size),
                .immediate(value: rotation, width: 16),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: G17 — FCMLA vector (0x64, bit21=0, bit15=0)

    @inline(__always)
    static func decodeFCMLAVector(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        guard let size = fpSize(e) else { return undefined(e, a) }
        let rotation = Int64((e >> 13) & 0b11) &* 90
        let da = zd(e), n = zn(e), m = zm(e), g = pg3(e)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcmla,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [
                vec(da, size), govern(g, .merging), vec(n, size), vec(m, size),
                .immediate(value: rotation, width: 16),
            ],
            scalableReads: ScalableRegisterSet.empty.insertingPredicate(g),
            scalableEffect: [.readsStreamingMode, .partialWrite],
        )
    }

    // MARK: G17 — FCMLA indexed (0x64, bit21=1, bits[15:12]=0001, bit23=1)

    @inline(__always)
    static func decodeFCMLAIndexed(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let rotation = Int64((e >> 10) & 0b11) &* 90
        let da = zd(e), n = zn(e)
        let size: ScalarSize
        let m: UInt8
        let lane: UInt8
        if (e >> 22) & 1 == 0 {
            // H form: 3-bit Zm, 2-bit index.
            size = .h
            m = UInt8((e >> 16) & 0b111)
            lane = UInt8((e >> 19) & 0b11)
        } else {
            // S form: 4-bit Zm, 1-bit index.
            size = .s
            m = UInt8((e >> 16) & 0b1111)
            lane = UInt8((e >> 20) & 0b1)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .fcmla,
            semanticReads: vecMask(da).union(vecMask(n)).union(vecMask(m)),
            semanticWrites: vecMask(da), category: .sve,
            operands: [
                vec(da, size), vec(n, size), vecIndexed(m, size, lane: lane),
                .immediate(value: rotation, width: 16),
            ],
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G18 — indexed FMLA/FMLS (0x64, bit21=1, bits[15:12]=0000)

    @inline(__always)
    static func decodeIndexedFMA(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let bf16 = (e >> 11) & 1 == 1
        if bf16, (e >> 23) & 1 == 1 { return undefined(e, a) } // bf16 lives in the b23=0 space
        let subtract = (e >> 10) & 1 == 1
        let mnemonic: Mnemonic = bf16
            ? (subtract ? .bfmls : .bfmla)
            : (subtract ? .fmls : .fmla)
        return indexedMultiplyDraft(e, a, mnemonic, accumulate: true)
    }

    // MARK: G18 — indexed FMUL (0x64, bit21=1, bits[15:12]=0010, bit10=0)

    @inline(__always)
    static func decodeIndexedFMUL(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        let bf16 = (e >> 11) & 1 == 1
        if bf16, (e >> 23) & 1 == 1 { return undefined(e, a) }
        return indexedMultiplyDraft(e, a, bf16 ? .bfmul : .fmul, accumulate: false)
    }

    /// Build the `<Zd>.<T>, <Zn>.<T>, <Zm>.<T>[i]` draft with the per-size
    /// index packing shared by the indexed FMA/FMUL forms: bit23=0 → `.h`
    /// (index bits[22,20:19], 3-bit Zm), bits[23:22]=10 → `.s` (index
    /// bits[20:19], 3-bit Zm), bits[23:22]=11 → `.d` (index bit20, 4-bit Zm).
    @inline(__always)
    static func indexedMultiplyDraft(
        _ e: UInt32, _ a: UInt64, _ mnemonic: Mnemonic, accumulate: Bool,
    ) -> DecodedDraft {
        let size: ScalarSize
        let m: UInt8
        let lane: UInt8
        if (e >> 23) & 1 == 0 {
            size = .h
            m = UInt8((e >> 16) & 0b111)
            let laneBits: UInt32 = ((e >> 20) & 0b100) | ((e >> 19) & 0b011)
            lane = UInt8(laneBits)
        } else if (e >> 22) & 1 == 0 {
            size = .s
            m = UInt8((e >> 16) & 0b111)
            lane = UInt8((e >> 19) & 0b11)
        } else {
            size = .d
            m = UInt8((e >> 16) & 0b1111)
            lane = UInt8((e >> 20) & 0b1)
        }
        let d = zd(e), n = zn(e)
        var reads = vecMask(n).union(vecMask(m))
        if accumulate { reads = reads.union(vecMask(d)) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: vecMask(d), category: .sve,
            operands: [vec(d, size), vec(n, size), vecIndexed(m, size, lane: lane)],
            scalableEffect: .readsStreamingMode,
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register pair (LDP/STP/LDPSW/STGP/LDNP/STNP)
// with all writeback variants. Encoding shell bits[29:24] = 101000..101011.
//
//   bits[24:23] indexing:
//     00 = no-allocate pair (LDNP/STNP)
//     01 = post-indexed pair
//     10 = signed-offset pair (no writeback)
//     11 = pre-indexed pair
//
//   bit[22] = L (0 = store, 1 = load)
//   bits[31:30] = opc:
//     00 = 32-bit pair (Wt/Wt2 — LDP/STP/LDNP/STNP)
//     01 = either LDPSW (load-sign-extend 32→64 into Xt/Xt2) or STGP (MTE)
//     10 = 64-bit pair (Xt/Xt2 — LDP/STP/LDNP/STNP)
//     11 = reserved (or SIMD-pair at V=1, which we don't reach)
//
//   imm7 at bits[21:15] is signed × scale (4 for the 32-bit pair and
//   LDPSW, 8 for the 64-bit pair, 16 for STGP — the MTE tag granule).
//
// Verified canonical:
//   ldp x1, xzr, [x0, #-8] = 0xA97FFC01 (signed offset)
//   ldp x0, x0, [x15], #16  = 0xA8C1...
//   ldp x0, x0, [x15, #16]! = 0xA9C1...

enum LoadStorePairDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let indexing = UInt8((encoding >> 23) & 0x3)
        let L = UInt8((encoding >> 22) & 1)
        let imm7 = (encoding >> 15) & 0x7F
        let Rt2 = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Determine mnemonic + width + scale.
        let mnemonic: Mnemonic
        let regWidth: RegisterWidth
        let scale: Int64
        switch (opc, L, indexing) {
        // opc=00 — 32-bit pair (LDP/STP/LDNP/STNP at Wt/Wt2).
        case (0b00, 1, 0b00): mnemonic = .ldnp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b00): mnemonic = .stnp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b01): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b01): mnemonic = .stp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b10): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b10): mnemonic = .stp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b11): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b11): mnemonic = .stp; regWidth = .w32; scale = 4
        // opc=01 — LDPSW (load) or STGP (store). LDPSW writes Xt/Xt2;
        // STGP stores 64-bit pair with MTE tag granule scale 16. No
        // no-allocate form for either (indexing=00 reserved).
        case (0b01, 1, 0b01), (0b01, 1, 0b10), (0b01, 1, 0b11):
            mnemonic = .ldpsw; regWidth = .x64; scale = 4
        case (0b01, 0, 0b01), (0b01, 0, 0b10), (0b01, 0, 0b11):
            mnemonic = .stgp; regWidth = .x64; scale = 16
        // opc=10 — 64-bit pair (LDP/STP/LDNP/STNP at Xt/Xt2).
        case (0b10, 1, 0b00): mnemonic = .ldnp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b00): mnemonic = .stnp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b01): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b01): mnemonic = .stp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b10): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b10): mnemonic = .stp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b11): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b11): mnemonic = .stp; regWidth = .x64; scale = 8
        // opc=11 — FEAT_LSUI unprivileged 64-bit pair (Xt/Xt2). no-allocate
        // (indexing=00) is LDTNP/STTNP; post/offset/pre are LDTP/STTP.
        case (0b11, 1, 0b00): mnemonic = .ldtnp; regWidth = .x64; scale = 8
        case (0b11, 0, 0b00): mnemonic = .sttnp; regWidth = .x64; scale = 8
        case (0b11, 1, 0b01), (0b11, 1, 0b10), (0b11, 1, 0b11):
            mnemonic = .ldtp; regWidth = .x64; scale = 8
        case (0b11, 0, 0b01), (0b11, 0, 0b10), (0b11, 0, 0b11):
            mnemonic = .sttp; regWidth = .x64; scale = 8
        // Every other (opc, L, indexing) falls through to `default` —
        // including LDPSW/STGP at indexing=00, which is reserved.
        default:
            return .undefined(at: address, encoding: encoding)
        }

        // indexing ∈ {00,01,10,11} all enumerated; 0b11 (pre-index) is `default`.
        let writeback: Writeback = switch indexing {
        case 0b00, 0b10: .none
        case 0b01: .postIndex
        default: .preIndex
        }

        let displacement = lsSignExtendImm7(imm7) * scale
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let memOperand = MemoryOperand(
            base: .register(rnRef),
            index: nil,
            displacement: displacement,
            extend: .none,
            shift: 0,
            writeback: writeback,
        )

        let reads: RegisterSet
        let writes: RegisterSet
        if L == 1 {
            // Load: read Rn (and Rn written if writeback), write Rt + Rt2.
            reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            var w = lsInsertingNonZero(reg: rtRef, into: .empty)
            w = lsInsertingNonZero(reg: rt2Ref, into: w)
            if writeback != .none {
                w = lsInsertingNonZero(reg: rnRef, into: w)
            }
            writes = w
        } else {
            // Store: read Rt + Rt2 + Rn; write Rn only if writeback.
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rtRef, into: r)
            r = lsInsertingNonZero(reg: rt2Ref, into: r)
            reads = r
            writes = writeback == .none
                ? .empty
                : lsInsertingNonZero(reg: rnRef, into: .empty)
        }

        let memoryAccess: MemoryAccess = L == 1 ? .load : .store

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .register(rt2Ref),
                .memory(memOperand),
            ],
        )
    }
}

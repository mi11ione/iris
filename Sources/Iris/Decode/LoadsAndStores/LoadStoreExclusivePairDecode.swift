// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store exclusive pair (LDXP/STXP/LDAXP/STLXP).
// Encoding shell: bits[29:24] = 001000, bit[23] = 0 (o2=0 → exclusive),
// bit[21] = 1 (pair), bits[15:10] = (o0, Rt2[4:0]).
//
// Discriminator (L, o0):
//   (L=0, o0=0) STXP — store-exclusive pair
//   (L=1, o0=0) LDXP — load-exclusive pair
//   (L=0, o0=1) STLXP — store-release exclusive pair
//   (L=1, o0=1) LDAXP — load-acquire exclusive pair
//
// size[31:30]: 10 = word pair (Wt, Wt2), 11 = dword pair (Xt, Xt2).
// Sizes 00 / 01 are reserved (UNDEFINED).
//
// Verified against `llvm-mc -show-encoding`:
//   ldxp  x0, x1, [x2]     = 0xC87F0440
//   stxp  w0, x1, x2, [x3] = 0xC8200861

enum LoadStoreExclusivePairDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // The top-level dispatcher routes here only when bit[31]=1, so
        // size[31:30] ∈ {0b10, 0b11} — word-pair or dword-pair. Byte/
        // halfword pair encodings have bit[31]=0 and are reserved; the
        // dispatcher sends those to the CASP path, which rejects them.
        let size = UInt8((encoding >> 30) & 0x3)
        let L = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let o0 = UInt8((encoding >> 15) & 1)
        let Rt2 = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let rtWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        let mnemonic: Mnemonic
        let memoryAccess: MemoryAccess
        let memoryOrdering: MemoryOrdering
        switch (L, o0) {
        case (0, 0):
            mnemonic = .stxp
            memoryAccess = .exclusiveStore
            memoryOrdering = []
        case (1, 0):
            mnemonic = .ldxp
            memoryAccess = .exclusiveLoad
            memoryOrdering = []
        case (0, 1):
            mnemonic = .stlxp
            memoryAccess = .exclusiveStore
            memoryOrdering = [.release]
        // (L,o0) ∈ {0,1}² — all four enumerated; (1,1)=LDAXP is `default`.
        default:
            mnemonic = .ldaxp
            memoryAccess = .exclusiveLoad
            memoryOrdering = [.acquire]
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        if L == 0 {
            // Store-exclusive pair: `<Ws>, <Wt|Xt>, <Wt2|Xt2>, [Xn|SP]`.
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            reads = lsInsertingNonZero(reg: rt2Ref, into: reads)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                semanticWrites: writes,
                branchClass: .none,
                memoryAccess: memoryAccess,
                memoryOrdering: memoryOrdering,
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [
                    .register(rsRef),
                    .register(rtRef),
                    .register(rt2Ref),
                    .memory(MemoryOperand(base: .register(rnRef))),
                ],
            )
        }

        // Load-exclusive pair: `<Wt|Xt>, <Wt2|Xt2>, [Xn|SP]`.
        var writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        writes = lsInsertingNonZero(reg: rt2Ref, into: writes)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .register(rt2Ref),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

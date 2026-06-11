// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store exclusive register (L2) + load-acquire/store-
// release (L4) + LOR LDLAR/STLLR (L4c). Shared encoding shell:
//   bits[29:24] = 001000
//   bit[21]      = 0 (this file handles bit[21]=0; bit[21]=1 is pair / CAS)
//
// Discriminator quartet (o2, L, o0):
//   (o2=0, L=0, o0=0) STXR / STXRB / STXRH       — store-exclusive
//   (o2=0, L=1, o0=0) LDXR / LDXRB / LDXRH       — load-exclusive
//   (o2=0, L=0, o0=1) STLXR / STLXRB / STLXRH    — store-release-exclusive
//   (o2=0, L=1, o0=1) LDAXR / LDAXRB / LDAXRH    — load-acquire-exclusive
//   (o2=1, L=0, o0=0) STLLR / STLLRB / STLLRH    — store-release LOR (FEAT_LOR)
//   (o2=1, L=1, o0=0) LDLAR / LDLARB / LDLARH    — load-acquire LOR (FEAT_LOR)
//   (o2=1, L=0, o0=1) STLR / STLRB / STLRH       — store-release
//   (o2=1, L=1, o0=1) LDAR / LDARB / LDARH       — load-acquire
//
// size[31:30] selects: 00=B, 01=H, 10=word (Wt), 11=dword (Xt).
//
// Verified against `llvm-mc -show-encoding`:
//   ldxr  x0, [x0]         = 0xC85F7C00
//   stxr  w0, x1, [x2]     = 0xC8007C41
//   ldaxr x0, [x0]         = 0xC85FFC00
//   stlxr w0, x1, [x2]     = 0xC800FC41
//   ldar  x0, [x0]         = 0xC8DFFC00
//   stlr  x0, [x0]         = 0xC89FFC00
//   ldlar x0, [x0]         = 0xC8DF7C00
//   stllr x0, [x0]         = 0xC89F7C00
//
// Operand shape (store-exclusive): `Ws, <Wt|Xt>, [Xn|SP]`. (Other forms):
// `<Wt|Xt>, [Xn|SP]` — no offset, no writeback.

enum LoadStoreExclusiveAndOrderedDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let o2 = UInt8((encoding >> 23) & 1)
        let L = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let o0 = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Width of Rt: byte/halfword/word load into Wt; dword load into Xt.
        let rtWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        // Map (size, o2, L, o0) → mnemonic. The fixed-field bits (Rt2 = 11111,
        // Rs = 11111 for non-store) are verified by llvm-mc; we decode-as-
        // encoded and emit the canonical mnemonic.
        let mnemonic: Mnemonic
        let memoryAccess: MemoryAccess
        let memoryOrdering: MemoryOrdering
        let isExclusiveStore = (o2 == 0 && L == 0)

        switch (o2, L, o0) {
        case (0, 0, 0):
            // STXR / STXRB / STXRH — store-exclusive
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .stxrb
            case 0b01: mnemonic = .stxrh
            default: mnemonic = .stxr
            }
            memoryAccess = .exclusiveStore
            memoryOrdering = []
        case (0, 1, 0):
            // LDXR / LDXRB / LDXRH — load-exclusive
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .ldxrb
            case 0b01: mnemonic = .ldxrh
            default: mnemonic = .ldxr
            }
            memoryAccess = .exclusiveLoad
            memoryOrdering = []
        case (0, 0, 1):
            // STLXR / STLXRB / STLXRH — store-release exclusive
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .stlxrb
            case 0b01: mnemonic = .stlxrh
            default: mnemonic = .stlxr
            }
            memoryAccess = .exclusiveStore
            memoryOrdering = [.release]
        case (0, 1, 1):
            // LDAXR / LDAXRB / LDAXRH — load-acquire exclusive
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .ldaxrb
            case 0b01: mnemonic = .ldaxrh
            default: mnemonic = .ldaxr
            }
            memoryAccess = .exclusiveLoad
            memoryOrdering = [.acquire]
        case (1, 0, 0):
            // STLLR / STLLRB / STLLRH — store-release LOR
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .stllrb
            case 0b01: mnemonic = .stllrh
            default: mnemonic = .stllr
            }
            memoryAccess = .store
            memoryOrdering = [.release]
        case (1, 1, 0):
            // LDLAR / LDLARB / LDLARH — load-acquire LOR
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .ldlarb
            case 0b01: mnemonic = .ldlarh
            default: mnemonic = .ldlar
            }
            memoryAccess = .load
            memoryOrdering = [.acquire]
        case (1, 0, 1):
            // STLR / STLRB / STLRH — store-release
            // size ∈ {00,01,10,11} all enumerated; word/dword → `default`.
            switch size {
            case 0b00: mnemonic = .stlrb
            case 0b01: mnemonic = .stlrh
            default: mnemonic = .stlr
            }
            memoryAccess = .store
            memoryOrdering = [.release]
        // (o2,L,o0) ∈ {0,1}³ — all eight combinations are enumerated;
        // (1,1,1)=LDAR is the last, made `default`.
        default:
            // LDAR / LDARB / LDARH — load-acquire.
            switch size {
            case 0b00: mnemonic = .ldarb
            case 0b01: mnemonic = .ldarh
            default: mnemonic = .ldar
            }
            memoryAccess = .load
            memoryOrdering = [.acquire]
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        // Exclusive-store form: `<Ws>, <Wt|Xt>, [Xn|SP]`.
        if isExclusiveStore {
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
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
                    .memory(MemoryOperand(base: .register(rnRef))),
                ],
            )
        }

        // Exclusive-load and ordered forms: `<Wt|Xt>, [Xn|SP]`. A load writes
        // Rt and reads the base; an ordered store (STLR/STLLR) instead reads
        // Rt as the stored data and writes nothing.
        let isLoad = memoryAccess == .load || memoryAccess == .exclusiveLoad
        let baseReads = lsInsertingNonZero(reg: rnRef, into: .empty)
        let writes: RegisterSet = isLoad
            ? lsInsertingNonZero(reg: rtRef, into: .empty)
            : .empty
        let finalReads: RegisterSet = isLoad
            ? baseReads
            : lsInsertingNonZero(reg: rtRef, into: baseReads)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: finalReads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

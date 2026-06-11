// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_LSUI unprivileged load/store exclusive + compare-and-swap.
// Encoding shell bits[29:24]=001001 (V=0); bit[21]=0 for every form.
//   o2 = bit[23]: 0 = exclusive (single register), 1 = compare-and-swap.
//   Within CAS: size ∈ {00,01} is the register-pair form (CASPT, sz=bit30),
//   size ∈ {10,11} the single form (CAST).
//   L = bit[22] (A, acquire) and o0 = bit[15] (R, release) select ordering.
// The `t` suffix marks the unprivileged (EL0 translation-regime) access.
// Mirrors the privileged shells (LoadStoreExclusiveAndOrderedDecode /
// CompareAndSwapDecode) at bits[29:24]=001000.

enum LSUILoadStoreDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bit[21] is 0 for every valid LSUI 001001 form.
        if (encoding >> 21) & 1 != 0 { return .undefined(at: address, encoding: encoding) }
        let size = UInt8((encoding >> 30) & 0x3)
        let o2 = (encoding >> 23) & 1
        if o2 == 0 {
            // Unprivileged exclusive (single register) — word/dword only.
            guard size == 0b10 || size == 0b11 else {
                return .undefined(at: address, encoding: encoding)
            }
            return decodeExclusive(encoding: encoding, address: address, size: size)
        }
        // Compare-and-swap — LSUI CAS/CASP are 64-bit only (CASPT at size=01,
        // CAST at size=11; the 32-bit size encodings are reserved). bits[14:10]
        // is SBZ (CONSTRAINED UNPREDICTABLE, not UNDEFINED — llvm-mc decodes a
        // nonzero value, so do we).
        if size == 0b01 {
            return decodeCASP(encoding: encoding, address: address)
        }
        if size == 0b11 {
            return decodeCAS(encoding: encoding, address: address)
        }
        return .undefined(at: address, encoding: encoding)
    }

    @inline(__always)
    private static func decodeExclusive(encoding: UInt32, address: UInt64, size: UInt8) -> DecodedDraft {
        let L = (encoding >> 22) & 1
        let o0 = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let rtWidth: RegisterWidth = size == 0b11 ? .x64 : .w32
        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        if L == 0 {
            // Store-exclusive: `Ws, <Wt|Xt>, [Xn|SP]`.
            let mnemonic: Mnemonic = o0 == 0 ? .sttxr : .stltxr
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: mnemonic,
                semanticReads: reads, semanticWrites: writes,
                branchClass: .none, memoryAccess: .exclusiveStore,
                memoryOrdering: o0 == 0 ? [] : [.release],
                flagEffect: .none, category: .loadsAndStores,
                operands: [
                    .register(rsRef), .register(rtRef),
                    .memory(MemoryOperand(base: .register(rnRef))),
                ],
            )
        }
        // Load-exclusive: `<Wt|Xt>, [Xn|SP]`.
        let mnemonic: Mnemonic = o0 == 0 ? .ldtxr : .ldatxr
        let reads = lsInsertingNonZero(reg: rnRef, into: .empty)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .exclusiveLoad,
            memoryOrdering: o0 == 0 ? [] : [.acquire],
            flagEffect: .none, category: .loadsAndStores,
            operands: [.register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))],
        )
    }

    @inline(__always)
    private static func decodeCAS(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let A = (encoding >> 22) & 1
        let R = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        // The caller routes only size == 0b11 here (CAST is 64-bit only;
        // the 32-bit size encodings are reserved).
        let regWidth: RegisterWidth = .x64
        let mnemonic: Mnemonic = switch (A, R) {
        case (0, 0): .cast
        case (1, 0): .casat
        case (0, 1): .caslt
        default: .casalt
        }
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }
        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
            flagEffect: .none, category: .loadsAndStores,
            operands: [
                .register(rsRef), .register(rtRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }

    @inline(__always)
    private static func decodeCASP(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let A = (encoding >> 22) & 1
        let R = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        // CASP requires even Rs/Rt (the pair base); odd is reserved.
        if (Rs & 1) != 0 || (Rt & 1) != 0 { return .undefined(at: address, encoding: encoding) }
        // The caller routes only size == 0b01 here (CASPT is 64-bit only).
        let regWidth: RegisterWidth = .x64
        let mnemonic: Mnemonic = switch (A, R) {
        case (0, 0): .caspt
        case (1, 0): .caspat
        case (0, 1): .casplt
        default: .caspalt
        }
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }
        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rs1Ref = lsGprOperand(encoding: Rs &+ 1, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rt1Ref = lsGprOperand(encoding: Rt &+ 1, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rs1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rt1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        var writes = lsInsertingNonZero(reg: rsRef, into: .empty)
        writes = lsInsertingNonZero(reg: rs1Ref, into: writes)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
            flagEffect: .none, category: .loadsAndStores,
            operands: [
                .register(rsRef), .register(rs1Ref),
                .register(rtRef), .register(rt1Ref),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

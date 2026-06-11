// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Compare-and-Swap family (class L5). `decode` handles the
// single-register forms CAS / CASA / CASL / CASAL and their B / H size
// variants; `decodeCASP` handles the register-pair forms CASP / CASPA /
// CASPL / CASPAL.
//
//   CAS encoding:   size  0010001  A  1  Rs  o0  11111  Rn  Rt
//   CASP encoding:  0 sz  0010000  A  1  Rs  o0  11111  Rn  Rt
//
// A (acquire) = bit[22], o0 (release) = bit[15]; bits[14:10] = 11111 is a
// fixed field. bit[23] = 1 distinguishes CAS from the pair shells; CASP
// has bit[23] = 0 and bit[31] = 0, with a 1-bit pair size at bit[30]. The
// top-level dispatcher reaches `decode` for the CAS shell and `decodeCASP`
// for the CASP shell.

enum CompareAndSwapDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // CAS encoding requires bits[14:10] = 11111 (FIXED). Any other
        // value is a reserved encoding; llvm-mc rejects as invalid.
        let bits14_10 = (encoding >> 10) & 0x1F
        if bits14_10 != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let size = UInt8((encoding >> 30) & 0x3)
        let A = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let R = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Width per size: 00=byte (Wt), 01=halfword (Wt), 10=word (Wt),
        // 11=dword (Xt).
        let regWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        // Mnemonic per (size, A, R).
        let mnemonic: Mnemonic = switch (size, A, R) {
        // CAS / CASA / CASL / CASAL (word/dword sizes).
        case (0b10, 0, 0), (0b11, 0, 0): .cas
        case (0b10, 1, 0), (0b11, 1, 0): .casa
        case (0b10, 0, 1), (0b11, 0, 1): .casl
        case (0b10, 1, 1), (0b11, 1, 1): .casal
        // CASB / CASAB / CASLB / CASALB.
        case (0b00, 0, 0): .casb
        case (0b00, 1, 0): .casab
        case (0b00, 0, 1): .caslb
        case (0b00, 1, 1): .casalb
        // CASH / CASAH / CASLH / CASALH.
        case (0b01, 0, 0): .cash
        case (0b01, 1, 0): .casah
        case (0b01, 0, 1): .caslh
        // size ∈ {00,01,10,11} × A,R ∈ {0,1} — all 16 combinations are
        // enumerated; (0b01,1,1)=CASALH is the last, made `default` so the
        // compiler-mandated catch-all is a live region.
        default: .casalh
        }

        // Memory ordering follows (A, R).
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        // CAS semantics: reads Rs (old expected) + Rt (replacement) + Rn (base);
        // writes Rs (actual old memory value loaded back).
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rsRef, into: .empty)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: ordering,
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rsRef),
                .register(rtRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }

    @_optimize(speed)
    static func decodeCASP(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // CASP requires bits[14:10] = 11111 (a fixed field). The dispatcher
        // routes the CASP shell here without inspecting bits[14:10], so this
        // guard is the reserved-encoding filter for the CASP path.
        let bits14_10 = (encoding >> 10) & 0x1F
        if bits14_10 != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let sz = UInt8((encoding >> 30) & 1)
        let A = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let R = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // CASP constraint: Rs and Rt must be even. Odd encodings are
        // CONSTRAINED UNPREDICTABLE and rejected by llvm-mc.
        // We match: emit UNDEFINED for odd-register CASP.
        if (Rs & 1) != 0 || (Rt & 1) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let regWidth: RegisterWidth = sz == 1 ? .x64 : .w32

        let mnemonic: Mnemonic
            // (A,R) ∈ {0,1}² — all four enumerated; (1,1)=CASPAL is `default`.
            = switch (A, R)
        {
        case (0, 0): .casp
        case (1, 0): .caspa
        case (0, 1): .caspl
        default: .caspal
        }

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rs1Ref = lsGprOperand(encoding: Rs &+ 1, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rt1Ref = lsGprOperand(encoding: Rt &+ 1, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        // CASP semantics: reads Rs/Rs+1 + Rt/Rt+1 + Rn; writes Rs/Rs+1.
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rs1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rt1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        var writes = lsInsertingNonZero(reg: rsRef, into: .empty)
        writes = lsInsertingNonZero(reg: rs1Ref, into: writes)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: ordering,
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rsRef),
                .register(rs1Ref),
                .register(rtRef),
                .register(rt1Ref),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

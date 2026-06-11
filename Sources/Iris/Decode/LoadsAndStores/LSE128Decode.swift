// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_LSE128 128-bit atomic memory operations. Encoding shell
// bits[29:24] = 011001, V=0, bit[21]=1, bits[11:10]=00.
//
//   bits[23:22] = (A, R) ordering: (0,0)=plain, (1,0)=A, (0,1)=L, (1,1)=AL.
//   bits[20:16] = Rs (second operand register).
//   bits[15:12] = op: 0001=ldclrp, 0011=ldsetp, 1000=swpp.
//   bits[9:5]  = Rn (base, SP-role at 31).
//   bits[4:0]  = Rt (first operand register).
//
// Rt and Rs must not be 31 (the ZR encoding is reserved → UNDEFINED).
// Operand order is `Xt, Xs, [Xn]`. Each is the low half of an even/odd
// 128-bit pair, but llvm-mc renders only the named register.

enum LSE128Decode {
    /// Per-op mnemonic rows, indexed `[opSlot][ordering]` with ordering
    /// 0=plain, 1=A, 2=L, 3=AL.
    private static let mnemonicsByOp: [[Mnemonic]] = [
        [.ldclrp, .ldclrpa, .ldclrpl, .ldclrpal],
        [.ldsetp, .ldsetpa, .ldsetpl, .ldsetpal],
        [.swpp, .swppa, .swppl, .swppal],
    ]

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // The dispatcher routes only size == 00 here (nonzero sizes fall
        // to RCW-pair / MTE / UNDEFINED upstream).
        let A = UInt8((encoding >> 23) & 1)
        let R = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let op = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // ZR-role encoding of Rt/Rs is reserved here.
        if Rt == 31 || Rs == 31 {
            return .undefined(at: address, encoding: encoding)
        }

        // op ∈ {0001, 0011, 1000} valid; map to a 0..2 slot.
        let opSlot: Int
        switch op {
        case 0b0001: opSlot = 0
        case 0b0011: opSlot = 1
        case 0b1000: opSlot = 2
        default: return .undefined(at: address, encoding: encoding)
        }

        // ordering slot: (A,R) -> 0=plain,1=A,2=L,3=AL.
        let ord = switch (A, R) {
        case (0, 0): 0
        case (1, 0): 1
        case (0, 1): 2
        default: 3
        }
        let mnemonic = mnemonicsByOp[opSlot][ord]

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rtRef = RegisterRef.x(Rt)
        let rsRef = RegisterRef.x(Rs)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        // Atomic RMW of the pair: reads Rt, Rs (compared/combined value) and
        // Rn; writes Rt (the loaded original pair).
        var reads = lsInsertingNonZero(reg: rtRef, into: .empty)
        reads = lsInsertingNonZero(reg: rsRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)

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
                .register(rtRef),
                .register(rsRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

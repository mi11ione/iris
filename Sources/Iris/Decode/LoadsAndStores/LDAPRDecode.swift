// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load-acquire RCpc register (FEAT_LRCPC). LDAPR family.
// Encoding shell bits[29:24] = 111000, bit[23] = 1, bit[22] = 0,
// bit[21] = 1, bits[20:16] = 11111, bits[15:12] = 1100, bits[11:10] = 00.
// Verified canonical: `ldapr x0, [x0]` = 0xF8BFC000.
//
// size[31:30] selects: 00=LDAPRB (Wt), 01=LDAPRH (Wt), 10=LDAPR (Wt),
// 11=LDAPR (Xt).
//
// Operand shape: `Rt, [Rn|SP]` — no offset, no writeback. MemoryAccess
// = .load. MemoryOrdering = .acquire (RCpc semantics are weaker than
// strong-acquire, but the classification collapses them; consumers use
// the mnemonic to distinguish).

enum LDAPRDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        switch size {
        case 0b00:
            mnemonic = .ldaprb
            rtWidth = .w32
        case 0b01:
            mnemonic = .ldaprh
            rtWidth = .w32
        case 0b10:
            mnemonic = .ldapr
            rtWidth = .w32
        // size ∈ {00,01,10,11} all enumerated; 0b11 (LDAPR Xt) is `default`.
        default:
            mnemonic = .ldapr
            rtWidth = .x64
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: lsInsertingNonZero(reg: rtRef, into: .empty),
            branchClass: .none,
            memoryAccess: .load,
            memoryOrdering: [.acquire],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .register(rtRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

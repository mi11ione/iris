// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_RPRES range prefetch (RPRFM). Shares the register-offset prefetch
// slot (bits[29:24] = 111000, V=0, size = 11, bit[21]=1, bits[11:10]=10)
// with PRFM (register). The discriminator is Rt<4:3> = 11: PRFM uses the
// 5-bit Rt as its prefetch operand, RPRFM steals that high pattern.
//
//   bits[20:16] = Rm — the 64-bit range register (Xm, ZR-role at 31).
//   bits[15:13] = option; option<1> (bit14) must be 1 (else UNDEFINED).
//   bit[12] = S.
//   bits[9:5] = Rn (base, SP-role at 31).
//   The 6-bit prefetch operand is option<2>:option<0>:S:Rt<2:0>; only
//   {0,1,4,5} have symbolic names (pldkeep/pstkeep/pldstrm/pststrm), the
//   rest render as `#N` (handled by the canonicalizer's rprfm branch).

enum RangePrefetchDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let option = UInt8((encoding >> 13) & 0x7)
        // option<1> is a fixed 1 in the RPRFM encoding.
        if (option & 0b010) == 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let S = UInt8((encoding >> 12) & 1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // 6-bit prefetch operand: option<2>:option<0>:S:Rt<2:0>.
        let prfop = (UInt8((option >> 2) & 1) << 5)
            | (UInt8(option & 1) << 4)
            | (S << 3)
            | (Rt & 0x7)

        let rmRef = lsGprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        // Reads Rm + Rn; pure prefetch hint, no register write.
        var reads = lsInsertingNonZero(reg: rmRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .rprfm,
            semanticReads: reads,
            semanticWrites: .empty,
            branchClass: .none,
            memoryAccess: .prefetch,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operands: [
                .immediate(value: Int64(prfop), width: 6),
                .register(rmRef),
                .memory(MemoryOperand(base: .register(rnRef))),
            ],
        )
    }
}

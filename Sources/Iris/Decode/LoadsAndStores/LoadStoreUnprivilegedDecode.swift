// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register, unprivileged (LDTR/STTR family).
// Same encoding shell as LDUR (bits[29:24] = 111000, V=0, bit[21]=0,
// imm9 at bits[20:12]) but with bits[11:10] = 10.
//
// size × opc table:
//   size=00 opc=00 STTRB
//   size=00 opc=01 LDTRB
//   size=00 opc=10 LDTRSB (sign-extend to Xt)
//   size=00 opc=11 LDTRSB (sign-extend to Wt)
//   size=01 opc=00 STTRH
//   size=01 opc=01 LDTRH
//   size=01 opc=10 LDTRSH (sign-extend to Xt)
//   size=01 opc=11 LDTRSH (sign-extend to Wt)
//   size=10 opc=00 STTR (Wt)
//   size=10 opc=01 LDTR (Wt)
//   size=10 opc=10 LDTRSW (sign-extend to Xt)
//   size=10 opc=11 reserved
//   size=11 opc=00 STTR (Xt)
//   size=11 opc=01 LDTR (Xt)
//   size=11 opc=10 reserved
//   size=11 opc=11 reserved
//
// Verified: `ldtr x0, [x0]` = 0xF8400800, `sttr x0, [x0]` = 0xF8000800.
// No prefetch variant in this class. No writeback.

enum LoadStoreUnprivilegedDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let displacement = lsSignExtendImm9(imm9)

        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        let memoryAccess: MemoryAccess
        let isLoad: Bool

        switch (size, opc) {
        case (0b00, 0b00): mnemonic = .sttrb; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b00, 0b01): mnemonic = .ldtrb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b00, 0b10): mnemonic = .ldtrsb; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b00, 0b11): mnemonic = .ldtrsb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b00): mnemonic = .sttrh; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b01, 0b01): mnemonic = .ldtrh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b10): mnemonic = .ldtrsh; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b01, 0b11): mnemonic = .ldtrsh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b00): mnemonic = .sttr; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b10, 0b01): mnemonic = .ldtr; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b10): mnemonic = .ldtrsw; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b00): mnemonic = .sttr; rtWidth = .x64; memoryAccess = .store; isLoad = false
        case (0b11, 0b01): mnemonic = .ldtr; rtWidth = .x64; memoryAccess = .load; isLoad = true
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let reads: RegisterSet
        let writes: RegisterSet
        if isLoad {
            reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        } else {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rtRef, into: r)
            reads = r
            writes = .empty
        }

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
                .memory(MemoryOperand(
                    base: .register(rnRef),
                    index: nil,
                    displacement: displacement,
                    extend: .none,
                    shift: 0,
                    writeback: .none,
                )),
            ],
        )
    }
}

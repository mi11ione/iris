// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register, immediate post-indexed (L8) and
// pre-indexed (L10). Same encoding shell as LDUR (bits[29:24] = 111000,
// V=0, bit[21]=0), distinguished only by bits[11:10]: 01 = post-index,
// 11 = pre-index.
//
// size × opc table is identical to L7 (LDUR/STUR) for the load/store
// kind discrimination. PRFM has no pre/post-index forms (the equivalent
// opc=11 size=11 encoding is reserved here).

enum LoadStoreIndexedDecode {
    @_optimize(speed)
    static func decode(
        encoding: UInt32, address: UInt64, writebackKind: Writeback,
    ) -> DecodedDraft {
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
        case (0b00, 0b00): mnemonic = .strb; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b00, 0b01): mnemonic = .ldrb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b00, 0b10): mnemonic = .ldrsb; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b00, 0b11): mnemonic = .ldrsb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b00): mnemonic = .strh; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b01, 0b01): mnemonic = .ldrh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b10): mnemonic = .ldrsh; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b01, 0b11): mnemonic = .ldrsh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b00): mnemonic = .str; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b10, 0b01): mnemonic = .ldr; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b10): mnemonic = .ldrsw; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b00): mnemonic = .str; rtWidth = .x64; memoryAccess = .store; isLoad = false
        case (0b11, 0b01): mnemonic = .ldr; rtWidth = .x64; memoryAccess = .load; isLoad = true
        default:
            // The indexed class has no PRFM form, so size=11/opc=10
            // (PRFM in the offset classes), size=10/opc=11, and
            // size=11/opc=11 are all unallocated → reserved.
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let reads: RegisterSet
        var writes: RegisterSet
        if isLoad {
            reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        } else {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rtRef, into: r)
            reads = r
            writes = .empty
        }
        // Pre/post-index always writes back the base register.
        writes = lsInsertingNonZero(reg: rnRef, into: writes)

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
                    writeback: writebackKind,
                )),
            ],
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register, unscaled immediate (LDUR/STUR
// family) + PRFUM. Encoding shell bits[29:24] = 111000, V=0, bit[21]=0,
// bits[11:10] = 00.
//
// size[31:30] × opc[23:22] selects the instruction:
//   size=00 opc=00 STURB   (store byte)
//   size=00 opc=01 LDURB   (load byte, zero-extend to Wt)
//   size=00 opc=10 LDURSB  (load byte, sign-extend to Xt)
//   size=00 opc=11 LDURSB  (load byte, sign-extend to Wt)
//   size=01 opc=00 STURH   (store halfword)
//   size=01 opc=01 LDURH   (load halfword, zero-extend to Wt)
//   size=01 opc=10 LDURSH  (load halfword, sign-extend to Xt)
//   size=01 opc=11 LDURSH  (load halfword, sign-extend to Wt)
//   size=10 opc=00 STUR (Wt)
//   size=10 opc=01 LDUR (Wt)
//   size=10 opc=10 LDURSW (load word, sign-extend to Xt)
//   size=10 opc=11 reserved
//   size=11 opc=00 STUR (Xt)
//   size=11 opc=01 LDUR (Xt)
//   size=11 opc=10 PRFUM (prefetch unscaled)
//   size=11 opc=11 reserved
//
// imm9 at bits[20:12] is a 9-bit signed unscaled byte offset (range -256
// to +255).
//
// Operand shape: Rt, [Rn|SP{, #simm9}]. PRFUM uses .prefetchOperation in
// the Rt slot.

enum LoadStoreUnscaledDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm9 = (encoding >> 12) & 0x1FF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let displacement = lsSignExtendImm9(imm9)

        // Determine mnemonic, register width, and access type.
        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        let memoryAccess: MemoryAccess
        let isLoad: Bool

        switch (size, opc) {
        case (0b00, 0b00): mnemonic = .sturb; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b00, 0b01): mnemonic = .ldurb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b00, 0b10): mnemonic = .ldursb; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b00, 0b11): mnemonic = .ldursb; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b00): mnemonic = .sturh; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b01, 0b01): mnemonic = .ldurh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b01, 0b10): mnemonic = .ldursh; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b01, 0b11): mnemonic = .ldursh; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b00): mnemonic = .stur; rtWidth = .w32; memoryAccess = .store; isLoad = false
        case (0b10, 0b01): mnemonic = .ldur; rtWidth = .w32; memoryAccess = .load; isLoad = true
        case (0b10, 0b10): mnemonic = .ldursw; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b00): mnemonic = .stur; rtWidth = .x64; memoryAccess = .store; isLoad = false
        case (0b11, 0b01): mnemonic = .ldur; rtWidth = .x64; memoryAccess = .load; isLoad = true
        case (0b11, 0b10):
            // PRFUM <prfop>, [Rn|SP{, #simm9}]
            let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .prfum,
                semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty,
                branchClass: .none,
                memoryAccess: .prefetch,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operands: [
                    .prefetchOperation(PrefetchOperation(rawValue: Rt)),
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
        default:
            // size=10/opc=11 and size=11/opc=11 — reserved encodings.
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

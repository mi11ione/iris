// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Load/store register, unsigned offset (scaled imm12).
// Encoding shell bits[29:24] = 111001, V=0. imm12 at bits[21:10].
//
// size × opc table is identical to LDUR for the load/store kind selection.
// The imm12 field is unsigned and scaled by (1 << size) bytes.

enum LoadStoreUnsignedOffsetDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let opc = UInt8((encoding >> 22) & 0x3)
        let imm12 = (encoding >> 10) & 0xFFF
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        // Displacement = imm12 × scale (1 << size).
        let scale: Int64 = 1 << Int64(size)
        let displacement = Int64(imm12) * scale

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
        case (0b11, 0b10):
            // PRFM <prfop>, [Rn|SP{, #pimm}]
            let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .prfm,
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

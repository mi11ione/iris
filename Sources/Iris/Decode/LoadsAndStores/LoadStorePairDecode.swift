// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LoadStorePairDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let indexing = UInt8((encoding >> 23) & 0x3)
        let L = UInt8((encoding >> 22) & 1)
        let imm7 = (encoding >> 15) & 0x7F
        let Rt2 = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let mnemonic: Mnemonic
        let regWidth: RegisterWidth
        let scale: Int64
        switch (opc, L, indexing) {
        case (0b00, 1, 0b00): mnemonic = .ldnp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b00): mnemonic = .stnp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b01): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b01): mnemonic = .stp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b10): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b10): mnemonic = .stp; regWidth = .w32; scale = 4
        case (0b00, 1, 0b11): mnemonic = .ldp; regWidth = .w32; scale = 4
        case (0b00, 0, 0b11): mnemonic = .stp; regWidth = .w32; scale = 4
        case (0b01, 1, 0b01), (0b01, 1, 0b10), (0b01, 1, 0b11):
            mnemonic = .ldpsw; regWidth = .x64; scale = 4
        case (0b01, 0, 0b01), (0b01, 0, 0b10), (0b01, 0, 0b11):
            mnemonic = .stgp; regWidth = .x64; scale = 16
        case (0b10, 1, 0b00): mnemonic = .ldnp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b00): mnemonic = .stnp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b01): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b01): mnemonic = .stp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b10): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b10): mnemonic = .stp; regWidth = .x64; scale = 8
        case (0b10, 1, 0b11): mnemonic = .ldp; regWidth = .x64; scale = 8
        case (0b10, 0, 0b11): mnemonic = .stp; regWidth = .x64; scale = 8
        case (0b11, 1, 0b00): mnemonic = .ldtnp; regWidth = .x64; scale = 8
        case (0b11, 0, 0b00): mnemonic = .sttnp; regWidth = .x64; scale = 8
        case (0b11, 1, 0b01), (0b11, 1, 0b10), (0b11, 1, 0b11):
            mnemonic = .ldtp; regWidth = .x64; scale = 8
        case (0b11, 0, 0b01), (0b11, 0, 0b10), (0b11, 0, 0b11):
            mnemonic = .sttp; regWidth = .x64; scale = 8
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let writeback: Writeback = switch indexing {
        case 0b00, 0b10: .none
        case 0b01: .postIndex
        default: .preIndex
        }

        let displacement = lsSignExtendImm7(imm7) * scale
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let memOperand = MemoryOperand(
            base: .register(rnRef),
            index: nil,
            displacement: displacement,
            extend: .none,
            shift: 0,
            writeback: writeback,
        )

        let reads: RegisterSet
        let writes: RegisterSet
        if L == 1 {
            reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            var w = lsInsertingNonZero(reg: rtRef, into: .empty)
            w = lsInsertingNonZero(reg: rt2Ref, into: w)
            if writeback != .none {
                w = lsInsertingNonZero(reg: rnRef, into: w)
            }
            writes = w
        } else {
            var r = lsInsertingNonZero(reg: rnRef, into: .empty)
            r = lsInsertingNonZero(reg: rtRef, into: r)
            r = lsInsertingNonZero(reg: rt2Ref, into: r)
            reads = r
            writes = writeback == .none
                ? .empty
                : lsInsertingNonZero(reg: rnRef, into: .empty)
        }

        let memoryAccess: MemoryAccess = L == 1 ? .load : .store

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
            operandCount: sink.emit(.register(rtRef), .register(rt2Ref), .memory(memOperand)),
        )
    }
}

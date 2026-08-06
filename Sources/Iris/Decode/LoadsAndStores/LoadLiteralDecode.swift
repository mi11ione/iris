// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LoadLiteralDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opc = UInt8((encoding >> 30) & 0x3)
        let imm19 = (encoding >> 5) & 0x7FFFF
        let Rt = UInt8(encoding & 0x1F)

        let displacement = lsSignExtendImm19(imm19) << 2

        let mnemonic: Mnemonic
        let rtOperand: Operand
        let memoryAccess: MemoryAccess
        var writes: RegisterSet = .empty

        switch opc {
        case 0b00:
            mnemonic = .ldr
            let rt = lsGprOperand(encoding: Rt, width: .w32, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        case 0b01:
            mnemonic = .ldr
            let rt = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        case 0b10:
            mnemonic = .ldrsw
            let rt = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
            rtOperand = .register(rt)
            writes = lsInsertingNonZero(reg: rt, into: .empty)
            memoryAccess = .load
        default:
            mnemonic = .prfm
            rtOperand = .prefetchOperation(PrefetchOperation(rawValue: Rt))
            memoryAccess = .prefetch
        }

        let memOperand: Operand = .memory(MemoryOperand(
            base: .pc,
            index: nil,
            displacement: displacement,
            extend: .none,
            shift: 0,
            writeback: .none,
        ))

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: .empty,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(rtOperand, memOperand),
        )
    }
}

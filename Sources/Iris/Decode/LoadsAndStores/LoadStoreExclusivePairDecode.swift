// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LoadStoreExclusivePairDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let L = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let o0 = UInt8((encoding >> 15) & 1)
        let Rt2 = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let rtWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        let mnemonic: Mnemonic
        let memoryAccess: MemoryAccess
        let memoryOrdering: MemoryOrdering
        switch (L, o0) {
        case (0, 0):
            mnemonic = .stxp
            memoryAccess = .exclusiveStore
            memoryOrdering = []
        case (1, 0):
            mnemonic = .ldxp
            memoryAccess = .exclusiveLoad
            memoryOrdering = []
        case (0, 1):
            mnemonic = .stlxp
            memoryAccess = .exclusiveStore
            memoryOrdering = [.release]
        default:
            mnemonic = .ldaxp
            memoryAccess = .exclusiveLoad
            memoryOrdering = [.acquire]
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rt2Ref = lsGprOperand(encoding: Rt2, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        if L == 0 {
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            reads = lsInsertingNonZero(reg: rt2Ref, into: reads)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                semanticWrites: writes,
                branchClass: .none,
                memoryAccess: memoryAccess,
                memoryOrdering: memoryOrdering,
                flagEffect: .none,
                category: .loadsAndStores,
                operandCount: sink.emit(.register(rsRef), .register(rtRef), .register(rt2Ref), .memory(MemoryOperand(base: .register(rnRef)))),
            )
        }

        var writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        writes = lsInsertingNonZero(reg: rt2Ref, into: writes)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .register(rt2Ref), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

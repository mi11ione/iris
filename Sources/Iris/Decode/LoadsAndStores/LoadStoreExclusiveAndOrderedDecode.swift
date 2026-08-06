// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LoadStoreExclusiveAndOrderedDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let o2 = UInt8((encoding >> 23) & 1)
        let L = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let o0 = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let rtWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        let mnemonic: Mnemonic
        let memoryAccess: MemoryAccess
        let memoryOrdering: MemoryOrdering
        let isExclusiveStore = (o2 == 0 && L == 0)

        switch (o2, L, o0) {
        case (0, 0, 0):
            switch size {
            case 0b00: mnemonic = .stxrb
            case 0b01: mnemonic = .stxrh
            default: mnemonic = .stxr
            }
            memoryAccess = .exclusiveStore
            memoryOrdering = []
        case (0, 1, 0):
            switch size {
            case 0b00: mnemonic = .ldxrb
            case 0b01: mnemonic = .ldxrh
            default: mnemonic = .ldxr
            }
            memoryAccess = .exclusiveLoad
            memoryOrdering = []
        case (0, 0, 1):
            switch size {
            case 0b00: mnemonic = .stlxrb
            case 0b01: mnemonic = .stlxrh
            default: mnemonic = .stlxr
            }
            memoryAccess = .exclusiveStore
            memoryOrdering = [.release]
        case (0, 1, 1):
            switch size {
            case 0b00: mnemonic = .ldaxrb
            case 0b01: mnemonic = .ldaxrh
            default: mnemonic = .ldaxr
            }
            memoryAccess = .exclusiveLoad
            memoryOrdering = [.acquire]
        case (1, 0, 0):
            switch size {
            case 0b00: mnemonic = .stllrb
            case 0b01: mnemonic = .stllrh
            default: mnemonic = .stllr
            }
            memoryAccess = .store
            memoryOrdering = [.release]
        case (1, 1, 0):
            switch size {
            case 0b00: mnemonic = .ldlarb
            case 0b01: mnemonic = .ldlarh
            default: mnemonic = .ldlar
            }
            memoryAccess = .load
            memoryOrdering = [.acquire]
        case (1, 0, 1):
            switch size {
            case 0b00: mnemonic = .stlrb
            case 0b01: mnemonic = .stlrh
            default: mnemonic = .stlr
            }
            memoryAccess = .store
            memoryOrdering = [.release]
        default:
            switch size {
            case 0b00: mnemonic = .ldarb
            case 0b01: mnemonic = .ldarh
            default: mnemonic = .ldar
            }
            memoryAccess = .load
            memoryOrdering = [.acquire]
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        if isExclusiveStore {
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
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
                operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
            )
        }

        let isLoad = memoryAccess == .load || memoryAccess == .exclusiveLoad
        let baseReads = lsInsertingNonZero(reg: rnRef, into: .empty)
        let writes: RegisterSet = isLoad
            ? lsInsertingNonZero(reg: rtRef, into: .empty)
            : .empty
        let finalReads: RegisterSet = isLoad
            ? baseReads
            : lsInsertingNonZero(reg: rtRef, into: baseReads)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: finalReads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

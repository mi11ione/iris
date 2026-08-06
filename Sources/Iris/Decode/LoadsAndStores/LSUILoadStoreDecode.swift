// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LSUILoadStoreDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 21) & 1 != 0 { return .undefined(at: address, encoding: encoding) }
        let size = UInt8((encoding >> 30) & 0x3)
        let o2 = (encoding >> 23) & 1
        if o2 == 0 {
            guard size == 0b10 || size == 0b11 else {
                return .undefined(at: address, encoding: encoding)
            }
            return decodeExclusive(encoding: encoding, address: address, size: size, &sink)
        }
        if size == 0b01 {
            return decodeCASP(encoding: encoding, address: address, &sink)
        }
        if size == 0b11 {
            return decodeCAS(encoding: encoding, address: address, &sink)
        }
        return .undefined(at: address, encoding: encoding)
    }

    @inline(__always)
    private static func decodeExclusive(encoding: UInt32, address: UInt64, size: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let L = (encoding >> 22) & 1
        let o0 = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let rtWidth: RegisterWidth = size == 0b11 ? .x64 : .w32
        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        if L == 0 {
            let mnemonic: Mnemonic = o0 == 0 ? .sttxr : .stltxr
            let rsRef = lsGprOperand(encoding: Rs, width: .w32, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = lsInsertingNonZero(reg: rtRef, into: reads)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address, encoding: encoding, mnemonic: mnemonic,
                semanticReads: reads, semanticWrites: writes,
                branchClass: .none, memoryAccess: .exclusiveStore,
                memoryOrdering: o0 == 0 ? [] : [.release],
                flagEffect: .none, category: .loadsAndStores,
                operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
            )
        }
        let mnemonic: Mnemonic = o0 == 0 ? .ldtxr : .ldatxr
        let reads = lsInsertingNonZero(reg: rnRef, into: .empty)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .exclusiveLoad,
            memoryOrdering: o0 == 0 ? [] : [.acquire],
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    @inline(__always)
    private static func decodeCAS(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let A = (encoding >> 22) & 1
        let R = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        let regWidth: RegisterWidth = .x64
        let mnemonic: Mnemonic = switch (A, R) {
        case (0, 0): .cast
        case (1, 0): .casat
        case (0, 1): .caslt
        default: .casalt
        }
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }
        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    @inline(__always)
    private static func decodeCASP(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let A = (encoding >> 22) & 1
        let R = (encoding >> 15) & 1
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)
        if (Rs & 1) != 0 || (Rt & 1) != 0 { return .undefined(at: address, encoding: encoding) }
        let regWidth: RegisterWidth = .x64
        let mnemonic: Mnemonic = switch (A, R) {
        case (0, 0): .caspt
        case (1, 0): .caspat
        case (0, 1): .casplt
        default: .caspalt
        }
        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }
        let rsRef = lsGprOperand(encoding: Rs, width: regWidth, form: .zrOrGeneral)
        let rs1Ref = lsGprOperand(encoding: Rs &+ 1, width: regWidth, form: .zrOrGeneral)
        let rtRef = lsGprOperand(encoding: Rt, width: regWidth, form: .zrOrGeneral)
        let rt1Ref = lsGprOperand(encoding: Rt &+ 1, width: regWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        var reads = lsInsertingNonZero(reg: rsRef, into: .empty)
        reads = lsInsertingNonZero(reg: rs1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rtRef, into: reads)
        reads = lsInsertingNonZero(reg: rt1Ref, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        var writes = lsInsertingNonZero(reg: rsRef, into: .empty)
        writes = lsInsertingNonZero(reg: rs1Ref, into: writes)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            branchClass: .none, memoryAccess: .atomic, memoryOrdering: ordering,
            flagEffect: .none, category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rs1Ref), .register(rtRef), .register(rt1Ref), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

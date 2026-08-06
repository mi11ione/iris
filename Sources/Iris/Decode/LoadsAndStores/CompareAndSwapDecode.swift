// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CompareAndSwapDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bits14_10 = (encoding >> 10) & 0x1F
        if bits14_10 != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let size = UInt8((encoding >> 30) & 0x3)
        let A = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let R = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let regWidth: RegisterWidth = (size == 0b11) ? .x64 : .w32

        let mnemonic: Mnemonic = switch (size, A, R) {
        case (0b10, 0, 0), (0b11, 0, 0): .cas
        case (0b10, 1, 0), (0b11, 1, 0): .casa
        case (0b10, 0, 1), (0b11, 0, 1): .casl
        case (0b10, 1, 1), (0b11, 1, 1): .casal
        case (0b00, 0, 0): .casb
        case (0b00, 1, 0): .casab
        case (0b00, 0, 1): .caslb
        case (0b00, 1, 1): .casalb
        case (0b01, 0, 0): .cash
        case (0b01, 1, 0): .casah
        case (0b01, 0, 1): .caslh
        default: .casalh
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
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: ordering,
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }

    @_optimize(speed)
    static func decodeCASP(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bits14_10 = (encoding >> 10) & 0x1F
        if bits14_10 != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let sz = UInt8((encoding >> 30) & 1)
        let A = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let R = UInt8((encoding >> 15) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if (Rs & 1) != 0 || (Rt & 1) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let regWidth: RegisterWidth = sz == 1 ? .x64 : .w32

        let mnemonic: Mnemonic
            = switch (A, R)
        {
        case (0, 0): .casp
        case (1, 0): .caspa
        case (0, 1): .caspl
        default: .caspal
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
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .atomic,
            memoryOrdering: ordering,
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rsRef), .register(rs1Ref), .register(rtRef), .register(rt1Ref), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

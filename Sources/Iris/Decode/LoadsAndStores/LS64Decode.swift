// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LS64Decode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let op = UInt8((encoding >> 12) & 0xF)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if (Rt & 1) != 0 || Rt > 22 {
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef = RegisterRef.x(Rt)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
        let rnOperand = Operand.memory(MemoryOperand(base: .register(rnRef)))

        switch op {
        case 0b1101:
            if Rs != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ld64b,
                semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty.inserting(rtRef),
                branchClass: .none,
                memoryAccess: .load,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operandCount: sink.emit(.register(rtRef), rnOperand),
            )
        case 0b1001:
            if Rs != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = reads.inserting(rtRef)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .st64b,
                semanticReads: reads,
                semanticWrites: .empty,
                branchClass: .none,
                memoryAccess: .store,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operandCount: sink.emit(.register(rtRef), rnOperand),
            )
        default:
            let mnemonic: Mnemonic = (op == 0b1011) ? .st64bv : .st64bv0
            let rsRef = lsGprOperand(encoding: Rs, width: .x64, form: .zrOrGeneral)
            var reads = lsInsertingNonZero(reg: rnRef, into: .empty)
            reads = reads.inserting(rtRef)
            let writes = lsInsertingNonZero(reg: rsRef, into: .empty)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: reads,
                semanticWrites: writes,
                branchClass: .none,
                memoryAccess: .store,
                memoryOrdering: [],
                flagEffect: .none,
                category: .loadsAndStores,
                operandCount: sink.emit(.register(rsRef), .register(rtRef), rnOperand),
            )
        }
    }
}

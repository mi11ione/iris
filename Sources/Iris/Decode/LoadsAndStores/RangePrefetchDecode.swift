// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum RangePrefetchDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let option = UInt8((encoding >> 13) & 0x7)
        if (option & 0b010) == 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let S = UInt8((encoding >> 12) & 1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let prfop = (UInt8((option >> 2) & 1) << 5)
            | (UInt8(option & 1) << 4)
            | (S << 3)
            | (Rt & 0x7)

        let rmRef = lsGprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        var reads = lsInsertingNonZero(reg: rmRef, into: .empty)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .rprfm,
            semanticReads: reads,
            semanticWrites: .empty,
            branchClass: .none,
            memoryAccess: .prefetch,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.immediate(value: Int64(prfop), width: 6), .register(rmRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

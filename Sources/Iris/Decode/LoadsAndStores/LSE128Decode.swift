// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LSE128Decode {
    /// Per-op mnemonic rows, indexed `[opSlot][ordering]` with ordering
    /// 0=plain, 1=A, 2=L, 3=AL.
    private static let mnemonicsByOp: [[Mnemonic]] = [
        [.ldclrp, .ldclrpa, .ldclrpl, .ldclrpal],
        [.ldsetp, .ldsetpa, .ldsetpl, .ldsetpal],
        [.swpp, .swppa, .swppl, .swppal],
    ]

    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let A = UInt8((encoding >> 23) & 1)
        let R = UInt8((encoding >> 22) & 1)
        let Rs = UInt8((encoding >> 16) & 0x1F)
        let op = UInt8((encoding >> 12) & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        if Rt == 31 || Rs == 31 {
            return .undefined(at: address, encoding: encoding)
        }

        let opSlot: Int
        switch op {
        case 0b0001: opSlot = 0
        case 0b0011: opSlot = 1
        case 0b1000: opSlot = 2
        default: return .undefined(at: address, encoding: encoding)
        }

        let ord = switch (A, R) {
        case (0, 0): 0
        case (1, 0): 1
        case (0, 1): 2
        default: 3
        }
        let mnemonic = mnemonicsByOp[opSlot][ord]

        var ordering: MemoryOrdering = []
        if A == 1 { ordering.insert(.acquire) }
        if R == 1 { ordering.insert(.release) }

        let rtRef = RegisterRef.x(Rt)
        let rsRef = RegisterRef.x(Rs)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        var reads = lsInsertingNonZero(reg: rtRef, into: .empty)
        reads = lsInsertingNonZero(reg: rsRef, into: reads)
        reads = lsInsertingNonZero(reg: rnRef, into: reads)
        let writes = lsInsertingNonZero(reg: rtRef, into: .empty)

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
            operandCount: sink.emit(.register(rtRef), .register(rsRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

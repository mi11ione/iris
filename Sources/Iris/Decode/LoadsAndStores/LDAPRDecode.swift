// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LDAPRDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let mnemonic: Mnemonic
        let rtWidth: RegisterWidth
        switch size {
        case 0b00:
            mnemonic = .ldaprb
            rtWidth = .w32
        case 0b01:
            mnemonic = .ldaprh
            rtWidth = .w32
        case 0b10:
            mnemonic = .ldapr
            rtWidth = .w32
        default:
            mnemonic = .ldapr
            rtWidth = .x64
        }

        let rtRef = lsGprOperand(encoding: Rt, width: rtWidth, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: lsInsertingNonZero(reg: rtRef, into: .empty),
            branchClass: .none,
            memoryAccess: .load,
            memoryOrdering: [.acquire],
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(base: .register(rnRef)))),
        )
    }
}

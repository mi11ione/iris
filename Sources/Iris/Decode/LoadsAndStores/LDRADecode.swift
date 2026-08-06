// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LDRADecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let size = UInt8((encoding >> 30) & 0x3)
        if size != 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        let M = UInt8((encoding >> 23) & 1)
        let S = UInt8((encoding >> 22) & 1)
        let imm9 = (encoding >> 12) & 0x1FF
        let W = UInt8((encoding >> 11) & 1)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rt = UInt8(encoding & 0x1F)

        let imm10 = (UInt32(S) << 9) | (imm9 & 0x1FF)
        let displacement = lsSignExtendImm10(imm10) * 8

        let mnemonic: Mnemonic = M == 0 ? .ldraa : .ldrab
        let rtRef = lsGprOperand(encoding: Rt, width: .x64, form: .zrOrGeneral)
        let rnRef = lsGprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)

        let writeback: Writeback = W == 1 ? .preIndex : .none
        var writes = lsInsertingNonZero(reg: rtRef, into: .empty)
        if writeback == .preIndex {
            writes = lsInsertingNonZero(reg: rnRef, into: writes)
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: lsInsertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: writes,
            branchClass: .none,
            memoryAccess: .load,
            memoryOrdering: [],
            flagEffect: .none,
            category: .loadsAndStores,
            operandCount: sink.emit(.register(rtRef), .memory(MemoryOperand(
                base: .register(rnRef),
                index: nil,
                displacement: displacement,
                extend: .none,
                shift: 0,
                writeback: writeback,
            ))),
        )
    }
}

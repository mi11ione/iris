// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CondBranchDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let o0 = UInt8((encoding >> 4) & 1)
        let cond = ConditionCode(rawValue: UInt8(encoding & 0xF))!
        let imm19 = Int32(bitPattern: (encoding >> 5) & 0x7FFFF)
        let signed = (imm19 &<< 13) &>> 13
        let byteOffset = Int64(signed) &<< 2
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: o0 == 1 ? .bcCond : .bCond,
            branchClass: .conditional,
            flagEffect: .readsNZCV,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.conditionCode(cond), .label(byteOffset: byteOffset)),
        )
    }
}

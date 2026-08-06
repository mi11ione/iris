// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CompareBranchDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 1)
        let op = UInt8((encoding >> 24) & 1)
        let imm19 = Int32(bitPattern: (encoding >> 5) & 0x7FFFF)
        let signed = (imm19 &<< 13) &>> 13
        let byteOffset = Int64(signed) &<< 2
        let Rt = UInt8(encoding & 0x1F)
        let reg: RegisterRef = (sf == 1) ? .x(Rt) : .w(Rt)
        let mnemonic: Mnemonic = (op == 0) ? .cbz : .cbnz
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(reg),
            branchClass: .conditional,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(reg), .label(byteOffset: byteOffset)),
        )
    }
}

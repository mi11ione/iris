// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum TestBranchDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let b5 = UInt8((encoding >> 31) & 1)
        let op = UInt8((encoding >> 24) & 1)
        let b40 = UInt8((encoding >> 19) & 0x1F)
        let bitPos = (b5 << 5) | b40
        let imm14 = Int32(bitPattern: (encoding >> 5) & 0x3FFF)
        let signed = (imm14 &<< 18) &>> 18
        let byteOffset = Int64(signed) &<< 2
        let Rt = UInt8(encoding & 0x1F)
        let reg: RegisterRef = (b5 == 0) ? .w(Rt) : .x(Rt)
        let mnemonic: Mnemonic = (op == 0) ? .tbz : .tbnz
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(reg),
            branchClass: .conditional,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(reg), .unsignedImmediate(value: UInt64(bitPos), width: 6), .label(byteOffset: byteOffset)),
        )
    }
}

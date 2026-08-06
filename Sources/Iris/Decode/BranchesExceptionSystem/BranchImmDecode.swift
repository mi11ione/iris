// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum BranchImmDecode {
    @inline(__always)
    static func decodeB(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .b,
            branchClass: .direct,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.label(byteOffset: BranchImmDecode.signedOffset(encoding))),
        )
    }

    @inline(__always)
    static func decodeBL(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .bl,
            semanticWrites: RegisterSet.empty.inserting(.x(30)),
            branchClass: .call,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.label(byteOffset: BranchImmDecode.signedOffset(encoding))),
        )
    }

    @inline(__always)
    private static func signedOffset(_ encoding: UInt32) -> Int64 {
        let raw = Int32(bitPattern: encoding & 0x03FF_FFFF)
        let signed = (raw &<< 6) &>> 6
        return Int64(signed) &<< 2
    }
}

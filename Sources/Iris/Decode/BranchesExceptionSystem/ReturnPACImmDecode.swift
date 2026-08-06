// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum ReturnPACImmDecode {
    /// FEAT_PAuth_LR `RETAASPPC` / `RETABSPPC` — bit 21 selects the key and
    /// bits[20:5] carry the magnitude of a non-positive byte offset.
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 22) & 0x3 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        if encoding & 0x1F != 0x1F {
            return .undefined(at: address, encoding: encoding)
        }
        let imm16: UInt32 = (encoding >> 5) & 0xFFFF
        let offset = -(Int64(imm16) &* 4)
        let key: UInt32 = (encoding >> 21) & 1
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: key == 0 ? .retaasppc : .retabsppc,
            semanticReads: RegisterSet.empty.inserting(.x(30)).inserting(.sp()),
            branchClass: .return,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.immediate(value: offset, width: 18)),
        )
    }
}

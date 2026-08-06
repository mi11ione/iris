// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum TChangeDecode {
    /// Apple TIndex `TCHANGEB` / `TCHANGEF`. bits[20:16] select the form:
    /// bit 20 picks the immediate variant, bit 18 the backward direction and
    /// bit 17 the `nb` suffix; bits 19 and 16 must be zero.
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 21) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let form = UInt8((encoding >> 16) & 0x1F)
        if form & 0b01001 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let backward = form & 0b00100 != 0
        let noBranch = form & 0b00010 != 0
        let mnemonic: Mnemonic = if backward {
            noBranch ? .tchangebNb : .tchangeb
        } else {
            noBranch ? .tchangefNb : .tchangef
        }
        let Rd = UInt8(encoding & 0x1F)
        let rdRef: RegisterRef = (Rd == 31) ? .xzr() : .x(Rd)
        if form & 0b10000 != 0 {
            if (encoding >> 12) & 0xF != 0 {
                return .undefined(at: address, encoding: encoding)
            }
            let index: UInt32 = (encoding >> 5) & 0x7F
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticWrites: RegisterSet.empty.inserting(rdRef),
                category: .branchesExceptionSystem,
                operandCount: sink.emit(
                    .register(rdRef), .unsignedImmediate(value: UInt64(index), width: 7),
                ),
            )
        }
        if (encoding >> 10) & 0x3F != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let rnRef: RegisterRef = (Rn == 31) ? .xzr() : .x(Rn)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(rnRef),
            semanticWrites: RegisterSet.empty.inserting(rdRef),
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(rdRef), .register(rnRef)),
        )
    }
}

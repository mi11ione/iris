// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CondCompareDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let o2 = UInt8((encoding >> 10) & 0x3)
        let o3 = UInt8((encoding >> 4) & 0x1)

        if S != 1 { return .undefined(at: address, encoding: encoding) }
        if o3 != 0 { return .undefined(at: address, encoding: encoding) }
        if o2 != 0b00, o2 != 0b10 {
            return .undefined(at: address, encoding: encoding)
        }

        let cond = condFromBits(UInt8((encoding >> 12) & 0xF))
        let nzcv = UInt64(encoding & 0xF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let mnemonic: Mnemonic = op == 0 ? .ccmn : .ccmp

        if o2 == 0b00 {
            let Rm = UInt8((encoding >> 16) & 0x1F)
            let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: .empty,
                flagEffect: [.nzcv, .readsNZCV],
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rnRef), .register(rmRef), .unsignedImmediate(value: nzcv, width: 4), .conditionCode(cond)),
            )
        }
        let imm5 = UInt64((encoding >> 16) & 0x1F)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: .empty,
            flagEffect: [.nzcv, .readsNZCV],
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rnRef), .unsignedImmediate(value: imm5, width: 5), .unsignedImmediate(value: nzcv, width: 4), .conditionCode(cond)),
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AddSubImmDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let sh = UInt8((encoding >> 22) & 0x1)
        let imm12 = UInt16((encoding >> 10) & 0xFFF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdForm: RegisterEncodingForm = S == 0 ? .spOrGeneral : .zrOrGeneral
        let rnForm: RegisterEncodingForm = .spOrGeneral
        let rdRef = gprOperand(encoding: Rd, width: width, form: rdForm)
        let rnRef = gprOperand(encoding: Rn, width: width, form: rnForm)

        if op == 0, S == 0, sh == 0, imm12 == 0, Rn == 31 || Rd == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mov,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef)),
            )
        }

        if S == 1, Rd == 31 {
            let mnemonic: Mnemonic = op == 1 ? .cmp : .cmn
            let operandMark = sink.mark
            sink.append(.register(rnRef))
            sink.append(.unsignedImmediate(value: UInt64(imm12), width: 12))
            if sh == 1 { sink.append(.shiftAmount(kind: .lsl, amount: 12)) }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingImmediate,
                operandCount: sink.count(since: operandMark),
            )
        }

        let mnemonic: Mnemonic = if op == 0 {
            S == 0 ? .add : .adds
        } else {
            S == 0 ? .sub : .subs
        }
        let operandMark = sink.mark
        sink.append(.register(rdRef))
        sink.append(.register(rnRef))
        sink.append(.unsignedImmediate(value: UInt64(imm12), width: 12))
        if sh == 1 { sink.append(.shiftAmount(kind: .lsl, amount: 12)) }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? .nzcv : .none,
            category: .dataProcessingImmediate,
            operandCount: sink.count(since: operandMark),
        )
    }
}

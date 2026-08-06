// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CondSelectDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let op2 = UInt8((encoding >> 10) & 0x3)

        if S != 0 { return .undefined(at: address, encoding: encoding) }
        if op2 != 0b00, op2 != 0b01 {
            return .undefined(at: address, encoding: encoding)
        }

        let Rm = UInt8((encoding >> 16) & 0x1F)
        let cond = condFromBits(UInt8((encoding >> 12) & 0xF))
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        let baseMnemonic: Mnemonic = switch (op, op2) {
        case (0, 0b00): .csel
        case (0, 0b01): .csinc
        case (1, 0b00): .csinv
        default: .csneg
        }
        let condInvertable = (cond.rawValue >> 1) != 0b111
        let invertedCond = condFromBits(cond.rawValue ^ 1)

        if baseMnemonic == .csinc, Rn == 31, Rm == 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cset,
                semanticReads: .empty,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .conditionCode(invertedCond)),
            )
        }
        if baseMnemonic == .csinv, Rn == 31, Rm == 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .csetm,
                semanticReads: .empty,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .conditionCode(invertedCond)),
            )
        }
        if baseMnemonic == .csinc, Rn == Rm, Rn != 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cinc,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .conditionCode(invertedCond)),
            )
        }
        if baseMnemonic == .csinv, Rn == Rm, Rn != 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cinv,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .conditionCode(invertedCond)),
            )
        }
        if baseMnemonic == .csneg, Rn == Rm, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cneg,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .conditionCode(invertedCond)),
            )
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: baseMnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .readsNZCV,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef), .conditionCode(cond)),
        )
    }
}

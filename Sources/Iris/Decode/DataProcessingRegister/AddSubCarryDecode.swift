// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AddSubCarryDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode2 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if let flagM = FlagManipulationDecode.decode(encoding: encoding, address: address, &sink) {
            return flagM
        }
        if sf == 1, S == 0, (encoding >> 13) & 0x7 == 0b001 {
            let amount = UInt8((encoding >> 10) & 0x7)
            let rd = gprOperand(encoding: Rd, width: .x64, form: .spOrGeneral)
            let rn = gprOperand(encoding: Rn, width: .x64, form: .spOrGeneral)
            let rm = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            let rmOperand: Operand = amount == 0
                ? .register(rm)
                : .shiftedRegister(reg: rm, shift: .lsl, amount: amount)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: op == 0 ? .addpt : .subpt,
                semanticReads: insertingNonZero(reg: rm, into: insertingNonZero(reg: rn, into: .empty)),
                semanticWrites: insertingNonZero(reg: rd, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rd), .register(rn), rmOperand),
            )
        }
        if opcode2 != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        if op == 1, Rn == 31 {
            let mnemonic: Mnemonic = S == 1 ? .ngcs : .ngc
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: S == 1 ? [.nzcv, .readsC] : .readsC,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .register(rmRef)),
            )
        }

        let mnemonic: Mnemonic = if op == 0 {
            S == 0 ? .adc : .adcs
        } else {
            S == 0 ? .sbc : .sbcs
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? [.nzcv, .readsC] : .readsC,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
        )
    }
}

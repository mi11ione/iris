// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum MinMaxImmDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 29) & 0x3 != 0 || (encoding >> 20) & 0x3 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 18) & 0x3)
        let imm8 = UInt8((encoding >> 10) & 0xFF)
        let rn = UInt8((encoding >> 5) & 0x1F)
        let rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: rn, width: width, form: .zrOrGeneral)

        let mnemonic: Mnemonic
        let immOperand: Operand
        switch opc {
        case 0b00:
            mnemonic = .smax
            immOperand = .immediate(value: Int64(Int8(bitPattern: imm8)), width: 8)
        case 0b01:
            mnemonic = .umax
            immOperand = .unsignedImmediate(value: UInt64(imm8), width: 8)
        case 0b10:
            mnemonic = .smin
            immOperand = .immediate(value: Int64(Int8(bitPattern: imm8)), width: 8)
        default:
            mnemonic = .umin
            immOperand = .unsignedImmediate(value: UInt64(imm8), width: 8)
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), immOperand),
        )
    }
}

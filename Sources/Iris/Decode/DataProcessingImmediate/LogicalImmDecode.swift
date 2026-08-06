// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LogicalImmDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let n = UInt8((encoding >> 22) & 0x1)
        let immr = UInt8((encoding >> 16) & 0x3F)
        let imms = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let regSize: UInt8 = sf == 1 ? 64 : 32
        guard let wmask = DecodeBitMasks.decode(
            n: n, imms: imms, immr: immr, regSize: regSize,
        ) else {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdForm: RegisterEncodingForm = opc == 0b11 ? .zrOrGeneral : .spOrGeneral
        let rnForm: RegisterEncodingForm = .zrOrGeneral
        let rdRef = gprOperand(encoding: Rd, width: width, form: rdForm)
        let rnRef = gprOperand(encoding: Rn, width: width, form: rnForm)

        if opc == 0b11, Rd == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .tst,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rnRef), .unsignedImmediate(value: wmask, width: regSize)),
            )
        }

        if opc == 0b01, Rn == 31,
           !AliasPredicates.isMOVWRepresentable(wmask, regSize: regSize)
        {
            let displayValue = if regSize == 32 {
                Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: wmask)))
            } else {
                Int64(bitPattern: wmask)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mov,
                semanticReads: .empty,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .immediate(value: displayValue, width: regSize)),
            )
        }

        let mnemonic: Mnemonic = if opc == 0b00 {
            .and
        } else if opc == 0b01 {
            .orr
        } else if opc == 0b10 {
            .eor
        } else {
            .ands
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: opc == 0b11 ? .nzcv : .none,
            category: .dataProcessingImmediate,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: wmask, width: regSize)),
        )
    }
}

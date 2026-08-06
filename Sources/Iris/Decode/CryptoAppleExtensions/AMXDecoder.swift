// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Decodes one Apple AMX word.
struct AMXDecoder: Sendable {
    init() {}

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let field = AMXField(rawBits: encoding)
        let opcode = field.opcode
        let operandField = field.operandField

        let (mnemonic, useAmxField): (Mnemonic, Bool)
        switch opcode {
        case 0: (mnemonic, useAmxField) = (.amxLdx, true)
        case 1: (mnemonic, useAmxField) = (.amxLdy, true)
        case 2: (mnemonic, useAmxField) = (.amxStx, true)
        case 3: (mnemonic, useAmxField) = (.amxSty, true)
        case 4: (mnemonic, useAmxField) = (.amxLdz, true)
        case 5: (mnemonic, useAmxField) = (.amxStz, true)
        case 6: (mnemonic, useAmxField) = (.amxLdzi, true)
        case 7: (mnemonic, useAmxField) = (.amxStzi, true)
        case 8: (mnemonic, useAmxField) = (.amxExtrx, true)
        case 9: (mnemonic, useAmxField) = (.amxExtry, true)
        case 10: (mnemonic, useAmxField) = (.amxFma64, true)
        case 11: (mnemonic, useAmxField) = (.amxFms64, true)
        case 12: (mnemonic, useAmxField) = (.amxFma32, true)
        case 13: (mnemonic, useAmxField) = (.amxFms32, true)
        case 14: (mnemonic, useAmxField) = (.amxMac16, true)
        case 15: (mnemonic, useAmxField) = (.amxFma16, true)
        case 16: (mnemonic, useAmxField) = (.amxFms16, true)
        case 17:
            switch operandField {
            case 0: (mnemonic, useAmxField) = (.amxSet, true)
            case 1: (mnemonic, useAmxField) = (.amxClr, true)
            default: (mnemonic, useAmxField) = (.amxUnknownOp, false)
            }
        case 18: (mnemonic, useAmxField) = (.amxVecint, true)
        case 19: (mnemonic, useAmxField) = (.amxVecfp, true)
        case 20: (mnemonic, useAmxField) = (.amxMatint, true)
        case 21: (mnemonic, useAmxField) = (.amxMatfp, true)
        case 22: (mnemonic, useAmxField) = (.amxGenlut, true)
        default:
            (mnemonic, useAmxField) = (.amxUnknownOp, false)
        }

        var reads: RegisterSet = .empty
        let writes: RegisterSet = .empty
        if useAmxField, opcode != 17 {
            let xRef = gprOperand(encoding: operandField, width: .x64, form: .zrOrGeneral)
            reads = insertingNonZero(reg: xRef, into: reads)
        }

        let operand: Operand = useAmxField
            ? .amxField(field)
            : .amxUnknown(rawFields: encoding)
        return DecodedDraft(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: writes,
            flagEffect: .none, category: .amx,
            operandCount: sink.emit(operand),
        )
    }
}

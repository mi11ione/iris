// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// AMX top-level FamilyDecoder. Registers for op0 = 0 (the reserved
// tier — Apple's AMX coprocessor occupies parts of the formally-
// unallocated encoding space, and the dispatcher explicitly permits
// registration there). Recognises AMX by the canonical mask
// `(encoding & 0xFFFFFC00) == 0x00201000` and dispatches the 5-bit
// opcode field (bits[9:5]) through the corsix/amx-documented 23-opcode
// table. Encodings whose top mask matches but whose opcode is outside
// [0..22] — or opcode 17 with operand outside {0, 1} — are surfaced as
// `.amxUnknownOp` with an `.amxUnknown(rawFields:)` operand carrying
// the full 32-bit word for downstream analysis.

struct AMXDecoder: FamilyDecoder {
    static let amxOp0Values: Set<UInt8> = [0]

    init() {}

    var op0Values: Set<UInt8> {
        Self.amxOp0Values
    }

    @_optimize(speed)
    func decode(
        encoding: UInt32, address: UInt64, features _: Features,
    ) -> DecodedDraft {
        guard isAMXEncoding(encoding) else {
            return .undefined(at: address, encoding: encoding)
        }
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
            // set / clr — operand is a 5-bit immediate; 0 = set, 1 = clr;
            // other values are reserved → surface as amxUnknownOp.
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
            // Opcode ≥ 23: outside documented set. Hardware faults; the
            // decoder surfaces the encoding as amxUnknownOp with raw payload.
            (mnemonic, useAmxField) = (.amxUnknownOp, false)
        }

        // Non-opcode-17 documented ops use the 5-bit operand field as an
        // X-register index whose runtime value carries the structured AMX
        // payload. The decoder doesn't model the payload but it DOES model
        // the GPR read so downstream dataflow can track the dependency.
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
            operands: [operand],
        )
    }
}

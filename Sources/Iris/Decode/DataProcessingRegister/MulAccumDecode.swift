// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Data-processing 3-source (multiply-accumulate) decode.
// Encoding tier op0=0xD bit 24=1. (opc, isSub, sf) selects MADD/MSUB/
// SMADDL/SMSUBL/UMADDL/UMSUBL; (opc, isSub) of (010, 0) → SMULH and
// (110, 0) → UMULH; opc 011 → FEAT_CPA MADDPT/MSUBPT. Aliases MUL/MNEG/
// SMULL/SMNEGL/UMULL/UMNEGL with Ra=XZR. Reserved: op54 != 0; sf=0
// wide-multiply; SMULH/UMULH with Ra != 31 OR isSub != 0; opc23_21
// outside {000, 001, 010, 011, 101, 110}.

enum MulAccumDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op54 = UInt8((encoding >> 29) & 0x3)
        let opc = UInt8((encoding >> 21) & 0x7)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let isSub = UInt8((encoding >> 15) & 0x1)
        let Ra = UInt8((encoding >> 10) & 0x1F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if op54 != 0 { return .undefined(at: address, encoding: encoding) }

        let dstWidth: RegisterWidth = sf == 1 ? .x64 : .w32

        switch opc {
        case 0b000:
            // MADD / MSUB — same-size multiply-accumulate at sf=0 or sf=1.
            let rdRef = gprOperand(encoding: Rd, width: dstWidth, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: dstWidth, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: dstWidth, form: .zrOrGeneral)
            let raRef = gprOperand(encoding: Ra, width: dstWidth, form: .zrOrGeneral)
            if Ra == 31 {
                // MUL / MNEG alias.
                let mnemonic: Mnemonic = isSub == 0 ? .mul : .mneg
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: mnemonic,
                    semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingRegister,
                    operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
                )
            }
            let mnemonic: Mnemonic = isSub == 0 ? .madd : .msub
            let raReads = insertingNonZero(reg: raRef, into: .empty)
            let allReads = insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: raReads))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: allReads,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef), .register(raRef)],
            )

        case 0b001:
            // SMADDL / SMSUBL — sf=1 required; Rd/Ra = X, Rn/Rm = W.
            if sf == 0 { return .undefined(at: address, encoding: encoding) }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .w32, form: .zrOrGeneral)
            let raRef = gprOperand(encoding: Ra, width: .x64, form: .zrOrGeneral)
            if Ra == 31 {
                let mnemonic: Mnemonic = isSub == 0 ? .smull : .smnegl
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: mnemonic,
                    semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingRegister,
                    operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
                )
            }
            let mnemonic: Mnemonic = isSub == 0 ? .smaddl : .smsubl
            let raReads = insertingNonZero(reg: raRef, into: .empty)
            let allReads = insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: raReads))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: allReads,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef), .register(raRef)],
            )

        case 0b010:
            // SMULH — sf=1 required; isSub=0 fixed. Ra is architecturally
            // "should be 11111" but llvm-mc treats it as don't-care
            // (decodes regardless and discards Ra in display). Match.
            if sf == 0 { return .undefined(at: address, encoding: encoding) }
            if isSub != 0 { return .undefined(at: address, encoding: encoding) }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .smulh,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
            )

        case 0b101:
            // UMADDL / UMSUBL — sf=1 required; Rd/Ra = X, Rn/Rm = W.
            if sf == 0 { return .undefined(at: address, encoding: encoding) }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .w32, form: .zrOrGeneral)
            let raRef = gprOperand(encoding: Ra, width: .x64, form: .zrOrGeneral)
            if Ra == 31 {
                let mnemonic: Mnemonic = isSub == 0 ? .umull : .umnegl
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: mnemonic,
                    semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingRegister,
                    operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
                )
            }
            let mnemonic: Mnemonic = isSub == 0 ? .umaddl : .umsubl
            let raReads = insertingNonZero(reg: raRef, into: .empty)
            let allReads = insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: raReads))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: allReads,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef), .register(raRef)],
            )

        case 0b110:
            // UMULH — same don't-care Ra rule as SMULH (case 0b010 above).
            if sf == 0 { return .undefined(at: address, encoding: encoding) }
            if isSub != 0 { return .undefined(at: address, encoding: encoding) }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .umulh,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
            )

        case 0b011:
            // FEAT_CPA checked-pointer multiply-add: MADDPT (isSub=0) /
            // MSUBPT (isSub=1). 64-bit only; 4-operand, no MUL-style alias.
            if sf == 0 { return .undefined(at: address, encoding: encoding) }
            let rdRef = gprOperand(encoding: Rd, width: .x64, form: .zrOrGeneral)
            let rnRef = gprOperand(encoding: Rn, width: .x64, form: .zrOrGeneral)
            let rmRef = gprOperand(encoding: Rm, width: .x64, form: .zrOrGeneral)
            let raRef = gprOperand(encoding: Ra, width: .x64, form: .zrOrGeneral)
            let raReads = insertingNonZero(reg: raRef, into: .empty)
            let allReads = insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: raReads))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: isSub == 0 ? .maddpt : .msubpt,
                semanticReads: allReads,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .register(rmRef), .register(raRef)],
            )

        default:
            // opc ∈ {100, 111} — reserved in the 3-source tier.
            return .undefined(at: address, encoding: encoding)
        }
    }
}

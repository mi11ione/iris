// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Add/subtract with carry decode. Encoding tier op0=0xD
// bit 24=0 bits[23:21]=000. Aliases: NGC = SBC Rd, XZR, Rm;
// NGCS = SBCS Rd, XZR, Rm. FEAT_FlagM (RMIF / SETF8 / SETF16) shares this
// tier and is decoded by `FlagManipulationDecode`, invoked first.

enum AddSubCarryDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opcode2 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // FEAT_FlagM (RMIF / SETF8 / SETF16) shares this tier with non-zero
        // sub-fields; decode it before the opcode2 guard would reject it.
        if let flagM = FlagManipulationDecode.decode(encoding: encoding, address: address) {
            return flagM
        }
        // FEAT_CPA checked-pointer ADDPT / SUBPT share this tier: sf=1, S=0,
        // bits[15:13]=001, bits[12:10]=lsl amount. Rd/Rn are SP-capable, Rm
        // is a general register; op selects ADDPT (0) / SUBPT (1).
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
                operands: [.register(rd), .register(rn), rmOperand],
            )
        }
        // Add/subtract-with-carry proper requires opcode2 == 000000; any
        // other non-zero value in this slot is reserved.
        if opcode2 != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        // All ADC-family operands are ZR-form.
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        // NGC / NGCS aliases: op=1 + Rn=31. Drops Rn; mnemonic NGC (S=0)
        // or NGCS (S=1); flag effect inherited from base.
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
                operands: [.register(rdRef), .register(rmRef)],
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
            operands: [.register(rdRef), .register(rnRef), .register(rmRef)],
        )
    }
}

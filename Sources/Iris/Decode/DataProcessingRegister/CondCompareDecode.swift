// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Conditional compare decode. Encoding
// tier op0=0xD bit 24=0 bits 23:21=010. Bits 11:10 (o2) discriminate
// register form (00) vs immediate form (10). Reserved fixed-field
// violations: S != 1, o3 != 0, o2 ∈ {01, 11}.

enum CondCompareDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let o2 = UInt8((encoding >> 10) & 0x3)
        let o3 = UInt8((encoding >> 4) & 0x1)

        // Reserved fixed-field violations.
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
            // Register form: operand[1] is Rm.
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
                operands: [
                    .register(rnRef),
                    .register(rmRef),
                    .unsignedImmediate(value: nzcv, width: 4),
                    .conditionCode(cond),
                ],
            )
        }
        // Immediate form (o2 == 0b10): operand[1] is imm5.
        let imm5 = UInt64((encoding >> 16) & 0x1F)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: .empty,
            flagEffect: [.nzcv, .readsNZCV],
            category: .dataProcessingRegister,
            operands: [
                .register(rnRef),
                .unsignedImmediate(value: imm5, width: 5),
                .unsignedImmediate(value: nzcv, width: 4),
                .conditionCode(cond),
            ],
        )
    }
}

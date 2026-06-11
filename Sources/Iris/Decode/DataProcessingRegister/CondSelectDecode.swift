// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Conditional select decode. Encoding
// tier op0=0xD bit 24=0 bits 23:21=100. (op, op2) selects CSEL/CSINC/
// CSINV/CSNEG. Aliases CSET/CSETM/CINC/CINV/CNEG.
// Reserved fixed-field violations: S != 0, op2 ∈ {10, 11}.
// The cond-invertable rule `(cond >> 1) != 0b111` excludes AL (1110)
// and NV (1111) — at those cond values the alias does NOT trigger and
// the base mnemonic is emitted with the original cond.

enum CondSelectDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
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
        default: .csneg // (1, 0b01) — only remaining (op, op2).
        }
        let condInvertable = (cond.rawValue >> 1) != 0b111
        let invertedCond = condFromBits(cond.rawValue ^ 1)

        // Alias precedence — most-specific-first.

        // CSET: base CSINC, Rn=Rm=31, condInvertable.
        if baseMnemonic == .csinc, Rn == 31, Rm == 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cset,
                semanticReads: .empty,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .conditionCode(invertedCond)],
            )
        }
        // CSETM: base CSINV, Rn=Rm=31, condInvertable.
        if baseMnemonic == .csinv, Rn == 31, Rm == 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .csetm,
                semanticReads: .empty,
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .conditionCode(invertedCond)],
            )
        }
        // CINC: base CSINC, Rn=Rm, Rn != 31, condInvertable.
        if baseMnemonic == .csinc, Rn == Rm, Rn != 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cinc,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .conditionCode(invertedCond)],
            )
        }
        // CINV: base CSINV, Rn=Rm, Rn != 31, condInvertable.
        if baseMnemonic == .csinv, Rn == Rm, Rn != 31, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cinv,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .conditionCode(invertedCond)],
            )
        }
        // CNEG: base CSNEG, Rn=Rm, condInvertable. NO Rn != 31 restriction
        // — CNEG allows Rn=XZR. Verified empirically:
        // `0xDA9F07E0` (CSNEG x0, xzr, xzr, EQ) → `cneg x0, xzr, ne`.
        if baseMnemonic == .csneg, Rn == Rm, condInvertable {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .cneg,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .readsNZCV,
                category: .dataProcessingRegister,
                operands: [.register(rdRef), .register(rnRef), .conditionCode(invertedCond)],
            )
        }

        // Base mnemonic — no alias.
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: baseMnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .readsNZCV,
            category: .dataProcessingRegister,
            operands: [
                .register(rdRef), .register(rnRef), .register(rmRef),
                .conditionCode(cond),
            ],
        )
    }
}

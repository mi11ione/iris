// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Add/subtract (immediate) decode.
// Encoding bits 28:23 = 100010. Aliases: MOV (to/from SP) for ADD
// imm=0 sh=0, CMP for SUBS Rd=XZR, CMN for ADDS Rd=XZR.

enum AddSubImmDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let sh = UInt8((encoding >> 22) & 0x1)
        let imm12 = UInt16((encoding >> 10) & 0xFFF)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        // Register forms per the ARM ARM operand syntax (`<Xd|SP>` vs `<Xd>`):
        // ADD/SUB Rd is SP-form, ADDS/SUBS Rd is ZR-form; Rn is SP-form
        // for both.
        let rdForm: RegisterEncodingForm = S == 0 ? .spOrGeneral : .zrOrGeneral
        let rnForm: RegisterEncodingForm = .spOrGeneral
        let rdRef = gprOperand(encoding: Rd, width: width, form: rdForm)
        let rnRef = gprOperand(encoding: Rn, width: width, form: rnForm)

        // MOV (to/from SP) alias: ADD imm=0, sh=0, S=0, and (Rd=31 OR Rn=31).
        // Operand list: [Rd, Rn], both SP-form. Empirical:
        //   `91000020` add x0,x1,#0 → NOT MOV (neither is SP)
        //   `910003e0` add x0,sp,#0 → mov x0, sp
        //   `9100001f` add sp,x0,#0 → mov sp, x0
        //   `910003ff` add sp,sp,#0 → mov sp, sp
        if op == 0, S == 0, sh == 0, imm12 == 0, Rn == 31 || Rd == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mov,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [.register(rdRef), .register(rnRef)],
            )
        }

        // CMP / CMN aliases: S=1, Rd=31. Drops Rd from operand list.
        // CMP = SUBS Rd=XZR (op=1, S=1, Rd=31); CMN = ADDS Rd=XZR (op=0, S=1, Rd=31).
        if S == 1, Rd == 31 {
            let mnemonic: Mnemonic = op == 1 ? .cmp : .cmn
            var operands: [Operand] = []
            operands.reserveCapacity(sh == 1 ? 3 : 2)
            operands.append(.register(rnRef))
            operands.append(.unsignedImmediate(value: UInt64(imm12), width: 12))
            if sh == 1 { operands.append(.shiftAmount(kind: .lsl, amount: 12)) }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingImmediate,
                operands: operands,
            )
        }

        // Base ADD / ADDS / SUB / SUBS.
        let mnemonic: Mnemonic = if op == 0 {
            S == 0 ? .add : .adds
        } else {
            S == 0 ? .sub : .subs
        }
        var operands: [Operand] = []
        operands.reserveCapacity(sh == 1 ? 4 : 3)
        operands.append(.register(rdRef))
        operands.append(.register(rnRef))
        operands.append(.unsignedImmediate(value: UInt64(imm12), width: 12))
        if sh == 1 { operands.append(.shiftAmount(kind: .lsl, amount: 12)) }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? .nzcv : .none,
            category: .dataProcessingImmediate,
            operands: operands,
        )
    }
}

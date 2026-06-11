// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Logical (immediate) decode.
// Encoding bits 28:23 = 100100, op0=0x9, op1=0b100. Aliases:
//   - TST = ANDS Rd=XZR.
//   - MOV (bitmask) = ORR Rn=XZR AND NOT isMOVWRepresentable(value).
// Reserved: sf=0 with N=1; the DecodeBitMasks-internal reservations
// (len<1, S==size-1).

enum LogicalImmDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
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
        // Register forms per the ARM ARM operand syntax (`<Xd|SP>` vs `<Xd>`):
        // AND/ORR/EOR Rd is SP-form, ANDS Rd is ZR-form; Rn is always
        // ZR-form for logical-imm.
        let rdForm: RegisterEncodingForm = opc == 0b11 ? .zrOrGeneral : .spOrGeneral
        let rnForm: RegisterEncodingForm = .zrOrGeneral
        let rdRef = gprOperand(encoding: Rd, width: width, form: rdForm)
        let rnRef = gprOperand(encoding: Rn, width: width, form: rnForm)

        // TST alias: ANDS with Rd=XZR. Operand list: [Rn, #wmask].
        // Flag effect = .nzcv (ANDS is flag-setting).
        if opc == 0b11, Rd == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .tst,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rnRef),
                    .unsignedImmediate(value: wmask, width: regSize),
                ],
            )
        }

        // MOV (bitmask) alias: ORR with Rn=XZR AND value is NOT also
        // representable via MOVZ/MOVN. The latter check ensures llvm-mc's
        // alias-precedence chain matches (MOV-wide wins over MOV-bitmask
        // when both are possible — empirical: `32000020` ORR w0,wzr,#0x1
        // stays as `orr w0, wzr, #0x1` because 1 fits MOVZ).
        if opc == 0b01, Rn == 31,
           !AliasPredicates.isMOVWRepresentable(wmask, regSize: regSize)
        {
            // Signed-decimal display rule: 32-bit values sign-extend
            // through Int32 first so `0x80000001` renders as `#-2147483647`
            // (not `#2147483649`); matches llvm-mc's signed-decimal
            // convention for MOV-bitmask of high-bit-set 32-bit values.
            let displayValue = if regSize == 32 {
                Int64(Int32(bitPattern: UInt32(truncatingIfNeeded: wmask)))
            } else {
                Int64(bitPattern: wmask)
            }
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mov,
                semanticReads: .empty, // Rn = XZR → no read
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operands: [
                    .register(rdRef),
                    .immediate(value: displayValue, width: regSize),
                ],
            )
        }

        // Base AND / ORR / EOR / ANDS.
        let mnemonic: Mnemonic = if opc == 0b00 {
            .and
        } else if opc == 0b01 {
            .orr
        } else if opc == 0b10 {
            .eor
        } else {
            // `opc` is masked to two bits; final base form is ANDS.
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
            operands: [
                .register(rdRef),
                .register(rnRef),
                .unsignedImmediate(value: wmask, width: regSize),
            ],
        )
    }
}

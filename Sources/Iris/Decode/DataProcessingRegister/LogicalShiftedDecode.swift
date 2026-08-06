// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LogicalShiftedDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let shiftBits = UInt8((encoding >> 22) & 0x3)
        let N = UInt8((encoding >> 21) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imm6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if sf == 0, (imm6 & 0x20) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)
        let shiftKind: ShiftKind = switch shiftBits {
        case 0b00: .lsl
        case 0b01: .lsr
        case 0b10: .asr
        default: .ror
        }
        let setsFlags = opc == 0b11
        let baseFlagEffect: FlagEffect = setsFlags ? .nzcv : .none

        if opc == 0b01, N == 0, Rn == 31, shiftBits == 0b00, imm6 == 0 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mov,
                semanticReads: insertingNonZero(reg: rmRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), .register(rmRef)),
            )
        }

        if opc == 0b01, N == 1, Rn == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .mvn,
                semanticReads: insertingNonZero(reg: rmRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: .none,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rdRef), shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6)),
            )
        }

        if opc == 0b11, N == 0, Rd == 31 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .tst,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rnRef), shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6)),
            )
        }

        let mnemonic: Mnemonic = switch (opc, N) {
        case (0b00, 0): .and
        case (0b00, 1): .bic
        case (0b01, 0): .orr
        case (0b01, 1): .orn
        case (0b10, 0): .eor
        case (0b10, 1): .eon
        case (0b11, 0): .ands
        default: .bics
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: baseFlagEffect,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6)),
        )
    }

    /// Third operand: plain `.register` when shift is the no-op default,
    /// `.shiftedRegister` otherwise.
    @inline(__always)
    @_effects(readonly)
    private static func shiftedOrPlain(
        reg: RegisterRef, kind: ShiftKind, amount: UInt8,
    ) -> Operand {
        if kind == .lsl, amount == 0 {
            return .register(reg)
        }
        return .shiftedRegister(reg: reg, shift: kind, amount: amount)
    }
}

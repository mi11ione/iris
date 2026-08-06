// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum AddSubRegisterDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 21) & 1 == 0 {
            return decodeShifted(encoding: encoding, address: address, &sink)
        }
        return decodeExtended(encoding: encoding, address: address, &sink)
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeShifted(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let shiftBits = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imm6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if shiftBits == 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
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
        default: .asr
        }

        if S == 1, Rd == 31 {
            let mnemonic: Mnemonic = op == 1 ? .cmp : .cmn
            let operandMark = sink.mark
            sink.append(.register(rnRef))
            sink.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingRegister,
                operandCount: sink.count(since: operandMark),
            )
        }

        if op == 1, Rn == 31 {
            let mnemonic: Mnemonic = S == 1 ? .negs : .neg
            let operandMark = sink.mark
            sink.append(.register(rdRef))
            sink.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: S == 1 ? .nzcv : .none,
                category: .dataProcessingRegister,
                operandCount: sink.count(since: operandMark),
            )
        }

        let mnemonic: Mnemonic = if op == 0 {
            S == 0 ? .add : .adds
        } else {
            S == 0 ? .sub : .subs
        }
        let operandMark = sink.mark
        sink.append(.register(rdRef))
        sink.append(.register(rnRef))
        sink.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? .nzcv : .none,
            category: .dataProcessingRegister,
            operandCount: sink.count(since: operandMark),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeExtended(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        if (encoding >> 22) & 0x3 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let optionBits = UInt8((encoding >> 13) & 0x7)
        let imm3 = UInt8((encoding >> 10) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if imm3 > 4 {
            return .undefined(at: address, encoding: encoding)
        }

        let dstWidth: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdForm: RegisterEncodingForm = S == 1 ? .zrOrGeneral : .spOrGeneral
        let rdRef = gprOperand(encoding: Rd, width: dstWidth, form: rdForm)
        let rnRef = gprOperand(encoding: Rn, width: dstWidth, form: .spOrGeneral)

        let extendKind: ExtendKind = switch optionBits {
        case 0b000: .uxtb
        case 0b001: .uxth
        case 0b010: .uxtw
        case 0b011: .uxtx
        case 0b100: .sxtb
        case 0b101: .sxth
        case 0b110: .sxtw
        default: .sxtx
        }
        let rmWidth: RegisterWidth = (sf == 1 && (extendKind == .uxtx || extendKind == .sxtx)) ? .x64 : .w32
        let rmRef = gprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)

        if S == 1, Rd == 31 {
            let mnemonic: Mnemonic = op == 1 ? .cmp : .cmn
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingRegister,
                operandCount: sink.emit(.register(rnRef), .extendedRegister(reg: rmRef, extend: extendKind, shift: imm3)),
            )
        }

        let mnemonic: Mnemonic = if op == 0 {
            S == 0 ? .add : .adds
        } else {
            S == 0 ? .sub : .subs
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? .nzcv : .none,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .extendedRegister(reg: rmRef, extend: extendKind, shift: imm3)),
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

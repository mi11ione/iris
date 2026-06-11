// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Add/subtract shifted-register AND extended-register
// decode. Encoding tier op0=0x5 bit 24=1; bit 21 splits
// shifted (0) vs extended (1). Aliases:
// CMP/CMN (Rd=XZR + S=1), NEG/NEGS (Rn=XZR + op=1), CMP/CMN extended
// (Rd=XZR + S=1, retain extend operand).

enum AddSubRegisterDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bit 21 splits shifted (0) vs extended (1).
        if (encoding >> 21) & 1 == 0 {
            return decodeShifted(encoding: encoding, address: address)
        }
        return decodeExtended(encoding: encoding, address: address)
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeShifted(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        let shiftBits = UInt8((encoding >> 22) & 0x3)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let imm6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // ROR shift (11) is reserved for arithmetic.
        if shiftBits == 0b11 {
            return .undefined(at: address, encoding: encoding)
        }
        // Reserved: 32-bit imm6[5]=1.
        if sf == 0, (imm6 & 0x20) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        // Arithmetic shifted-register Rd and Rn are BOTH ZR-form.
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)
        let shiftKind: ShiftKind = switch shiftBits {
        case 0b00: .lsl
        case 0b01: .lsr
        default: .asr // shiftBits ∈ {00, 01, 10}; 11 (ROR) rejected upstream.
        }

        // CMP/CMN aliases: S=1 + Rd=XZR. Drops Rd from operand list;
        // mnemonic CMP (op=1) or CMN (op=0); flag effect inherited (.nzcv).
        if S == 1, Rd == 31 {
            let mnemonic: Mnemonic = op == 1 ? .cmp : .cmn
            var operands: [Operand] = []
            operands.reserveCapacity(2)
            operands.append(.register(rnRef))
            operands.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
                semanticWrites: .empty,
                flagEffect: .nzcv,
                category: .dataProcessingRegister,
                operands: operands,
            )
        }

        // NEG/NEGS aliases: op=1 + Rn=XZR. Drops Rn; mnemonic NEG (S=0)
        // or NEGS (S=1); flag effect inherited from base (.nzcv for NEGS).
        if op == 1, Rn == 31 {
            let mnemonic: Mnemonic = S == 1 ? .negs : .neg
            var operands: [Operand] = []
            operands.reserveCapacity(2)
            operands.append(.register(rdRef))
            operands.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                semanticReads: insertingNonZero(reg: rmRef, into: .empty),
                semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                flagEffect: S == 1 ? .nzcv : .none,
                category: .dataProcessingRegister,
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
        operands.reserveCapacity(3)
        operands.append(.register(rdRef))
        operands.append(.register(rnRef))
        operands.append(shiftedOrPlain(reg: rmRef, kind: shiftKind, amount: imm6))
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: S == 1 ? .nzcv : .none,
            category: .dataProcessingRegister,
            operands: operands,
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decodeExtended(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let op = UInt8((encoding >> 30) & 0x1)
        let S = UInt8((encoding >> 29) & 0x1)
        // Bits 23:22 are architecturally fixed at 00 for ADD/SUB-extended.
        // Any other value lies outside the extended-register encoding
        // map and must produce UNDEFINED (per ARM ARM C4.1.5).
        if (encoding >> 22) & 0x3 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let optionBits = UInt8((encoding >> 13) & 0x7)
        let imm3 = UInt8((encoding >> 10) & 0x7)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        // Reserved: imm3 ∈ {5, 6, 7}.
        if imm3 > 4 {
            return .undefined(at: address, encoding: encoding)
        }

        let dstWidth: RegisterWidth = sf == 1 ? .x64 : .w32
        // Extended-register Rn is ALWAYS spOrGeneral; Rd is
        // spOrGeneral when S=0, zrOrGeneral when S=1.
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
        default: .sxtx // 0b111 — only remaining 3-bit value.
        }
        // Rm width is Xn ONLY at (sf=1 AND extend ∈ {UXTX, SXTX});
        // every other (sf, extend) combination → Wn. Empirically verified.
        let rmWidth: RegisterWidth = (sf == 1 && (extendKind == .uxtx || extendKind == .sxtx)) ? .x64 : .w32
        let rmRef = gprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)

        // CMP/CMN extended aliases: S=1 + Rd=XZR. Drops Rd; mnemonic CMP
        // (op=1) or CMN (op=0); flag effect inherited (.nzcv).
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
                operands: [
                    .register(rnRef),
                    .extendedRegister(reg: rmRef, extend: extendKind, shift: imm3),
                ],
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
            operands: [
                .register(rdRef),
                .register(rnRef),
                .extendedRegister(reg: rmRef, extend: extendKind, shift: imm3),
            ],
        )
    }

    /// Third operand: plain `.register` when shift is the no-op default, `.shiftedRegister` otherwise.
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

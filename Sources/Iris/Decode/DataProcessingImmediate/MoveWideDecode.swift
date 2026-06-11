// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Move wide (immediate) decode.
// Encoding bits 28:23 = 100101, op0=0x9, op1=0b101. Aliases: MOV
// (wide / inverted wide) for MOVZ / MOVN when `Value != 0 OR hw == 0`.
// Reserved: opc=01; sf=0 with hw[1]=1. MOVK is read-modify-write on Rd.

enum MoveWideDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let hw = UInt8((encoding >> 21) & 0x3)
        let imm16 = UInt16((encoding >> 5) & 0xFFFF)
        let Rd = UInt8(encoding & 0x1F)

        // Reserved encodings.
        if opc == 0b01 { return .undefined(at: address, encoding: encoding) }
        if sf == 0, (hw & 0b10) != 0 { return .undefined(at: address, encoding: encoding) }

        let regSize: UInt8 = sf == 1 ? 64 : 32
        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let shiftAmount: UInt8 = hw &* 16 // 0, 16, 32, 48

        // MOV-wide alias (MOVZ → MOV when value != 0 OR hw == 0).
        // Empirical: `d2c00000` MOVZ x0,#0,lsl #32 stays as movz (NOT mov).
        if opc == 0b10 { // MOVZ
            let value64 = UInt64(imm16) << shiftAmount
            if value64 != 0 || hw == 0 {
                let displayValue = signExtendForMovWide(value64, regSize: regSize)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .mov,
                    semanticReads: .empty, // MOVZ writes-only Rd; no Rn
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [
                        .register(rdRef),
                        .immediate(value: displayValue, width: regSize),
                    ],
                )
            }
            // Fall through to base MOVZ.
        }

        // MOV-inverted-wide alias (MOVN → MOV). Two gates:
        // (1) `imm16 != 0 OR hw == 0` — when imm16=0, every hw produces
        //     the same Value (all-ones within width); llvm-mc keeps the
        //     base MOVN form to disambiguate. Empirical: `92a00000`
        //     MOVN x0,#0,lsl #16 stays as `movn` (NOT `mov`).
        // (2) `!isMOVZRepresentable(Value)` — MOVZ is the preferred
        //     wide-immediate form. When both MOVN and MOVZ could
        //     produce the same Value, llvm-mc preserves the MOVN
        //     encoding form (no MOV alias). Empirical: `129fffe0`
        //     MOVN w0,#0xFFFF (Value=0xFFFF0000) stays as `movn` because
        //     MOVZ w0,#0xFFFF,lsl #16 also produces 0xFFFF0000.
        if opc == 0b00, imm16 != 0 || hw == 0 {
            let value64 = UInt64(imm16) << shiftAmount
            let widthMask: UInt64 = regSize == 64 ? UInt64.max : UInt64(UInt32.max)
            let inverted: UInt64 = ~value64 & widthMask
            if !AliasPredicates.isMOVZRepresentable(inverted, regSize: regSize) {
                let displayValue = signExtendForMovWide(inverted, regSize: regSize)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .mov,
                    semanticReads: .empty,
                    semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operands: [
                        .register(rdRef),
                        .immediate(value: displayValue, width: regSize),
                    ],
                )
            }
        }

        // Base MOVN / MOVZ / MOVK.
        let mnemonic: Mnemonic = if opc == 0b00 {
            .movn
        } else if opc == 0b10 {
            .movz
        } else {
            // opc == 01 returned above as reserved; remaining base form is MOVK.
            .movk
        }
        var operands: [Operand] = []
        operands.reserveCapacity(hw != 0 ? 3 : 2)
        operands.append(.register(rdRef))
        operands.append(.unsignedImmediate(value: UInt64(imm16), width: 16))
        if hw != 0 {
            operands.append(.shiftAmount(kind: .lsl, amount: shiftAmount))
        }
        // MOVK preserves the un-replaced bits of Rd; Rd is BOTH read and
        // written. MOVN/MOVZ fully overwrite — write-only.
        let reads: RegisterSet = mnemonic == .movk
            ? insertingNonZero(reg: rdRef, into: .empty)
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operands: operands,
        )
    }

    /// Sign-extend the MOV-wide computed value to Int64 for display.
    /// 32-bit MOV alias must sign-extend via Int32 first so that
    /// `0xFFFFFFFF` renders as `#-1`, not `#4294967295`.
    @inline(__always)
    @_effects(readonly)
    static func signExtendForMovWide(_ value: UInt64, regSize: UInt8) -> Int64 {
        if regSize == 64 {
            return Int64(bitPattern: value)
        }
        // 32-bit: sign-extend through Int32.
        let v32 = UInt32(truncatingIfNeeded: value)
        return Int64(Int32(bitPattern: v32))
    }
}

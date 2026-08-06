// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum BitfieldDecode {
    @inline(__always)
    @_optimize(speed)
    @_effects(readonly)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opc = UInt8((encoding >> 29) & 0x3)
        let n = UInt8((encoding >> 22) & 0x1)
        let immr = UInt8((encoding >> 16) & 0x3F)
        let imms = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        if opc == 0b11 { return .undefined(at: address, encoding: encoding) }
        if n != sf { return .undefined(at: address, encoding: encoding) }
        if sf == 0, (immr & 0x20) != 0 || (imms & 0x20) != 0 {
            return .undefined(at: address, encoding: encoding)
        }

        let regSize: UInt8 = sf == 1 ? 64 : 32
        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)

        let isBFMFamily = opc == 0b01
        let isFullWidthBFM = isBFMFamily && immr == 0 && imms == (regSize &- 1)
        let baseReads = isBFMFamily && !isFullWidthBFM
            ? insertingNonZero(reg: rdRef, into: insertingNonZero(reg: rnRef, into: .empty))
            : insertingNonZero(reg: rnRef, into: .empty)
        let baseWrites = insertingNonZero(reg: rdRef, into: .empty)

        if opc == 0b00, immr == 0 {
            if imms == 7 {
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxtb,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .register(rnWn)),
                )
            }
            if imms == 15 {
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxth,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .register(rnWn)),
                )
            }
            if imms == 31, sf == 1 {
                let rnWn = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .sxtw,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .register(rnWn)),
                )
            }
        }

        if opc == 0b10, sf == 0, immr == 0 {
            if imms == 7 {
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .uxtb,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .register(rnRef)),
                )
            }
            if imms == 15 {
                return DecodedDraft(
                    address: address,
                    encoding: encoding,
                    mnemonic: .uxth,
                    semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                    semanticWrites: baseWrites,
                    flagEffect: .none,
                    category: .dataProcessingImmediate,
                    operandCount: sink.emit(.register(rdRef), .register(rnRef)),
                )
            }
        }

        if opc == 0b00, imms == regSize &- 1 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .asr,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(immr), width: 6)),
            )
        }

        if opc == 0b10, imms == regSize &- 1 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .lsr,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(immr), width: 6)),
            )
        }

        if opc == 0b10, imms != (regSize &- 1), imms &+ 1 == immr {
            let shift: UInt8 = regSize &- 1 &- imms
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .lsl,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(shift), width: 6)),
            )
        }

        if opc == 0b00, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .sbfiz,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(lsb), width: 6), .unsignedImmediate(value: UInt64(widthOp), width: 6)),
            )
        }

        if opc == 0b00, imms >= immr {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .sbfx,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(immr), width: 6), .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6)),
            )
        }

        if opc == 0b10, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ubfiz,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(lsb), width: 6), .unsignedImmediate(value: UInt64(widthOp), width: 6)),
            )
        }

        if opc == 0b10, imms >= immr {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ubfx,
                semanticReads: insertingNonZero(reg: rnRef, into: .empty),
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(immr), width: 6), .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6)),
            )
        }

        if opc == 0b01, Rn == 31, immr == 0 || imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .bfc,
                semanticReads: baseReads,
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .unsignedImmediate(value: UInt64(lsb), width: 6), .unsignedImmediate(value: UInt64(widthOp), width: 6)),
            )
        }

        if opc == 0b01, imms < immr {
            let lsb: UInt8 = (regSize &- immr) & (regSize &- 1)
            let widthOp: UInt8 = imms &+ 1
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .bfi,
                semanticReads: baseReads,
                semanticWrites: baseWrites,
                flagEffect: .none,
                category: .dataProcessingImmediate,
                operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(lsb), width: 6), .unsignedImmediate(value: UInt64(widthOp), width: 6)),
            )
        }

        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .bfxil,
            semanticReads: baseReads,
            semanticWrites: baseWrites,
            flagEffect: .none,
            category: .dataProcessingImmediate,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .unsignedImmediate(value: UInt64(immr), width: 6), .unsignedImmediate(value: UInt64(imms &- immr &+ 1), width: 6)),
        )
    }
}

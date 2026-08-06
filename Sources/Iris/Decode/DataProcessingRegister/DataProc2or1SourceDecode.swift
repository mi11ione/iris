// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum DataProc2or1SourceDecode {
    @inline(__always)
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let S = UInt8((encoding >> 29) & 0x1)
        if S != 0 { return .undefined(at: address, encoding: encoding) }
        if (encoding >> 30) & 0x1 == 0 {
            return decode2SourceOrCRC32(encoding: encoding, address: address, &sink)
        }
        return decode1Source(encoding: encoding, address: address, &sink)
    }

    @inline(__always)
    @_optimize(speed)
    private static func decode2SourceOrCRC32(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)
        let rmRef = gprOperand(encoding: Rm, width: width, form: .zrOrGeneral)

        switch opc6 {
        case 0b000010:
            return threeRegDraft(.udiv, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b000011:
            return threeRegDraft(.sdiv, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b001000:
            return threeRegDraft(.lsl, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b001001:
            return threeRegDraft(.lsr, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b001010:
            return threeRegDraft(.asr, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b001011:
            return threeRegDraft(.ror, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b010000:
            return crcDraft(.crc32b, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010001:
            return crcDraft(.crc32h, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010010:
            return crcDraft(.crc32w, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010011:
            return crcDraft(.crc32x, sf: sf, requireSF: 1, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010100:
            return crcDraft(.crc32cb, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010101:
            return crcDraft(.crc32ch, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010110:
            return crcDraft(.crc32cw, sf: sf, requireSF: 0, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b010111:
            return crcDraft(.crc32cx, sf: sf, requireSF: 1, Rd: Rd, Rn: Rn, Rm: Rm, encoding: encoding, address: address, &sink)
        case 0b011000:
            return threeRegDraft(.smax, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b011001:
            return threeRegDraft(.umax, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b011010:
            return threeRegDraft(.smin, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        case 0b011011:
            return threeRegDraft(.umin, rdRef: rdRef, rnRef: rnRef, rmRef: rmRef, encoding: encoding, address: address, &sink)
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }

    /// Three-register DPR draft.
    @inline(__always)
    private static func threeRegDraft(
        _ mnemonic: Mnemonic, rdRef: RegisterRef, rnRef: RegisterRef, rmRef: RegisterRef,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
        )
    }

    /// CRC32 draft with the sf/opc6-driven Rm-width rule.
    @inline(__always)
    private static func crcDraft(
        _ mnemonic: Mnemonic, sf: UInt8, requireSF: UInt8, Rd: UInt8, Rn: UInt8, Rm: UInt8,
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if sf != requireSF { return .undefined(at: address, encoding: encoding) }
        let rdRef = gprOperand(encoding: Rd, width: .w32, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: .w32, form: .zrOrGeneral)
        let rmWidth: RegisterWidth = requireSF == 1 ? .x64 : .w32
        let rmRef = gprOperand(encoding: Rm, width: rmWidth, form: .zrOrGeneral)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rmRef, into: insertingNonZero(reg: rnRef, into: .empty)),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef), .register(rmRef)),
        )
    }

    @inline(__always)
    @_optimize(speed)
    private static func decode1Source(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 0x1)
        let opcode2 = UInt8((encoding >> 16) & 0x1F)
        if opcode2 != 0 { return .undefined(at: address, encoding: encoding) }

        let opc6 = UInt8((encoding >> 10) & 0x3F)
        let Rn = UInt8((encoding >> 5) & 0x1F)
        let Rd = UInt8(encoding & 0x1F)

        let width: RegisterWidth = sf == 1 ? .x64 : .w32
        let rdRef = gprOperand(encoding: Rd, width: width, form: .zrOrGeneral)
        let rnRef = gprOperand(encoding: Rn, width: width, form: .zrOrGeneral)

        let mnemonic: Mnemonic = switch opc6 {
        case 0b000000: .rbit
        case 0b000001: .rev16
        case 0b000010:
            sf == 0 ? .rev : .rev32
        case 0b000011:
            sf == 0 ? .undefined : .rev
        case 0b000100: .clz
        case 0b000101: .cls
        case 0b000110: .ctz
        case 0b000111: .cnt
        case 0b001000: .abs
        default: .undefined
        }
        if mnemonic == .undefined {
            return .undefined(at: address, encoding: encoding)
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: insertingNonZero(reg: rnRef, into: .empty),
            semanticWrites: insertingNonZero(reg: rdRef, into: .empty),
            flagEffect: .none,
            category: .dataProcessingRegister,
            operandCount: sink.emit(.register(rdRef), .register(rnRef)),
        )
    }
}

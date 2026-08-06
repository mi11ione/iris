// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum SystemDecode {
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bits23_22 = UInt8((encoding >> 22) & 0x3)
        if bits23_22 == 0b01 {
            return decodeD128(encoding: encoding, address: address, &sink)
        }
        if bits23_22 == 0b10 {
            return TChangeDecode.decode(encoding: encoding, address: address, &sink)
        }
        if bits23_22 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let L = UInt8((encoding >> 21) & 1)
        let op0 = UInt8((encoding >> 19) & 0x3)
        if op0 == 0b01 {
            let Rt = UInt8(encoding & 0x1F)
            return SystemInstructionDecode.decode(
                encoding: encoding, address: address, L: L, Rt: Rt, &sink,
            )
        }
        if op0 == 0, L == 0 {
            let control = decodeControl(encoding: encoding, address: address, &sink)
            if control.mnemonic != .undefined {
                return control
            }
        }
        return SystemMoveDecode.decode(encoding: encoding, address: address, L: L, &sink)
    }

    /// FEAT_D128 forms (bits 23:22 = 01).
    @inline(__always)
    private static func decodeD128(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let L = UInt8((encoding >> 21) & 1)
        let op0 = UInt8((encoding >> 19) & 0x3)
        if op0 == 0b01, L == 0 {
            return SystemInstructionDecode.decodeSysp(encoding: encoding, address: address, &sink)
        }
        return SystemMoveDecode.decodeD128(encoding: encoding, address: address, L: L, &sink)
    }

    @inline(__always)
    private static func decodeControl(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bits15_12 = UInt8((encoding >> 12) & 0xF)
        switch bits15_12 {
        case 0b0010:
            if (encoding >> 16) & 0x7 != 0b011 || encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let imm7 = UInt8((encoding >> 5) & 0x7F)
            return HintDecode.decode(encoding: encoding, address: address, imm7: imm7, &sink)
        case 0b0011:
            if (encoding >> 16) & 0x7 != 0b011 || encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let CRm = UInt8((encoding >> 8) & 0xF)
            let op2 = UInt8((encoding >> 5) & 0x7)
            return BarrierDecode.decode(
                encoding: encoding, address: address, CRm: CRm, op2: op2, &sink,
            )
        case 0b0100:
            if encoding & 0x1F != 0x1F {
                return .undefined(at: address, encoding: encoding)
            }
            let op1 = UInt8((encoding >> 16) & 0x7)
            let CRm = UInt8((encoding >> 8) & 0xF)
            let op2 = UInt8((encoding >> 5) & 0x7)
            return MSRImmediateDecode.decode(
                encoding: encoding, address: address, op1: op1, CRm: CRm, op2: op2, &sink,
            )
        case 0b0001:
            if (encoding >> 16) & 0x7 != 0b011 {
                return .undefined(at: address, encoding: encoding)
            }
            if (encoding >> 8) & 0xF != 0 {
                return .undefined(at: address, encoding: encoding)
            }
            let op2 = UInt8((encoding >> 5) & 0x7)
            let Rt = UInt8(encoding & 0x1F)
            return WFXTDecode.decode(
                encoding: encoding, address: address, op2: op2, Rt: Rt, &sink,
            )
        default:
            return .undefined(at: address, encoding: encoding)
        }
    }
}

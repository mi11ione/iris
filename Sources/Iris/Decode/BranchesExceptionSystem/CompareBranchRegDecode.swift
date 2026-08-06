// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum CompareBranchRegDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let bits24 = UInt8((encoding >> 24) & 1)
        return bits24 == 0
            ? decodeRegisterClass(encoding: encoding, address: address, &sink)
            : decodeImmediate(encoding: encoding, address: address, &sink)
    }

    /// Register / byte / halfword forms (bits 31:24 ∈ {0x74, 0xF4}).
    @inline(__always)
    private static func decodeRegisterClass(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 1)
        let cc = UInt8((encoding >> 21) & 0x7)
        let Rm = UInt8((encoding >> 16) & 0x1F)
        let bits15_14 = UInt8((encoding >> 14) & 0x3)
        let Rt = UInt8(encoding & 0x1F)
        let byteOffset = imm9ByteOffset(encoding)

        let mnemonic: Mnemonic
        let width: Width
        switch bits15_14 {
        case 0b00:
            guard let m = registerMnemonic(cc) else {
                return .undefined(at: address, encoding: encoding)
            }
            mnemonic = m
            width = (sf == 1) ? .x : .w
        case 0b10:
            guard sf == 0, let m = byteMnemonic(cc) else {
                return .undefined(at: address, encoding: encoding)
            }
            mnemonic = m
            width = .w
        case 0b11:
            guard sf == 0, let m = halfwordMnemonic(cc) else {
                return .undefined(at: address, encoding: encoding)
            }
            mnemonic = m
            width = .w
        default:
            return .undefined(at: address, encoding: encoding)
        }

        let rtRef: RegisterRef = (width == .x) ? .x(Rt) : .w(Rt)
        let rmRef: RegisterRef = (width == .x) ? .x(Rm) : .w(Rm)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(rtRef).inserting(rmRef),
            branchClass: .conditional,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(rtRef), .register(rmRef), .label(byteOffset: byteOffset)),
        )
    }

    /// Immediate form (bits 31:24 ∈ {0x75, 0xF5}).
    @inline(__always)
    private static func decodeImmediate(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 14) & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let sf = UInt8((encoding >> 31) & 1)
        let cc = UInt8((encoding >> 21) & 0x7)
        let imm6 = UInt64((encoding >> 15) & 0x3F)
        let Rt = UInt8(encoding & 0x1F)
        let byteOffset = imm9ByteOffset(encoding)
        guard let mnemonic = immediateMnemonic(cc) else {
            return .undefined(at: address, encoding: encoding)
        }
        let rtRef: RegisterRef = (sf == 1) ? .x(Rt) : .w(Rt)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(rtRef),
            branchClass: .conditional,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(rtRef), .unsignedImmediate(value: imm6, width: 6), .label(byteOffset: byteOffset)),
        )
    }

    private enum Width { case w, x }

    /// imm9 (bits 13:5) sign-extended and scaled by 4.
    @inline(__always)
    private static func imm9ByteOffset(_ encoding: UInt32) -> Int64 {
        let imm9 = Int32(bitPattern: (encoding >> 5) & 0x1FF)
        let signed = (imm9 &<< 23) &>> 23
        return Int64(signed) &<< 2
    }

    /// cc → register-form mnemonic (gt/ge/hi/hs/eq/ne); nil for 100/101.
    @inline(__always)
    private static func registerMnemonic(_ cc: UInt8) -> Mnemonic? {
        switch cc {
        case 0b000: .cbgt
        case 0b001: .cbge
        case 0b010: .cbhi
        case 0b011: .cbhs
        case 0b110: .cbeq
        case 0b111: .cbne
        default: nil
        }
    }

    /// cc → immediate-form mnemonic (gt/lt/hi/lo/eq/ne); nil for 100/101.
    @inline(__always)
    private static func immediateMnemonic(_ cc: UInt8) -> Mnemonic? {
        switch cc {
        case 0b000: .cbgt
        case 0b001: .cblt
        case 0b010: .cbhi
        case 0b011: .cblo
        case 0b110: .cbeq
        case 0b111: .cbne
        default: nil
        }
    }

    /// cc → byte-form mnemonic (cbb*); nil for 100/101.
    @inline(__always)
    private static func byteMnemonic(_ cc: UInt8) -> Mnemonic? {
        switch cc {
        case 0b000: .cbbgt
        case 0b001: .cbbge
        case 0b010: .cbbhi
        case 0b011: .cbbhs
        case 0b110: .cbbeq
        case 0b111: .cbbne
        default: nil
        }
    }

    /// cc → halfword-form mnemonic (cbh*); nil for 100/101.
    @inline(__always)
    private static func halfwordMnemonic(_ cc: UInt8) -> Mnemonic? {
        switch cc {
        case 0b000: .cbhgt
        case 0b001: .cbhge
        case 0b010: .cbhhi
        case 0b011: .cbhhs
        case 0b110: .cbheq
        case 0b111: .cbhne
        default: nil
        }
    }
}

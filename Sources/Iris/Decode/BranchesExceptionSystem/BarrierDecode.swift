// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum BarrierDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, CRm: UInt8, op2: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        switch op2 {
        case 0b010:
            decodeCLREX(encoding: encoding, address: address, CRm: CRm, &sink)
        case 0b100:
            decodeDSB(encoding: encoding, address: address, CRm: CRm, &sink)
        case 0b101:
            decodeDMB(encoding: encoding, address: address, CRm: CRm, &sink)
        case 0b110:
            decodeISB(encoding: encoding, address: address, CRm: CRm, &sink)
        case 0b111:
            decodeSB(encoding: encoding, address: address)
        case 0b001:
            decodeDSBnXS(encoding: encoding, address: address, CRm: CRm, &sink)
        default:
            .undefined(at: address, encoding: encoding)
        }
    }

    @inline(__always)
    private static func decodeCLREX(encoding: UInt32, address: UInt64, CRm: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let operandMark = sink.mark
        if CRm != 0xF {
            sink.append(.unsignedImmediate(value: UInt64(CRm), width: 4))
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .clrex,
            category: .branchesExceptionSystem,
            operandCount: sink.count(since: operandMark),
        )
    }

    @inline(__always)
    private static func decodeDSB(encoding: UInt32, address: UInt64, CRm: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        if CRm == 0 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .ssbb,
                category: .branchesExceptionSystem,
            )
        }
        if CRm == 4 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .pssbb,
                category: .branchesExceptionSystem,
            )
        }
        if CRm == 12 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .dfb,
                category: .branchesExceptionSystem,
            )
        }
        return decodeDSBOrDMB(encoding: encoding, address: address, CRm: CRm, mnemonic: .dsb, &sink)
    }

    @inline(__always)
    private static func decodeDMB(encoding: UInt32, address: UInt64, CRm: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        decodeDSBOrDMB(encoding: encoding, address: address, CRm: CRm, mnemonic: .dmb, &sink)
    }

    @inline(__always)
    private static func decodeDSBOrDMB(
        encoding: UInt32, address: UInt64, CRm: UInt8, mnemonic: Mnemonic, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        if let option = BarrierOption(rawOptionBits: CRm) {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: mnemonic,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.barrierOption(option)),
            )
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.unsignedImmediate(value: UInt64(CRm), width: 4)),
        )
    }

    @inline(__always)
    private static func decodeISB(encoding: UInt32, address: UInt64, CRm: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        let operandMark = sink.mark
        if CRm != 0xF {
            sink.append(.unsignedImmediate(value: UInt64(CRm), width: 4))
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .isb,
            category: .branchesExceptionSystem,
            operandCount: sink.count(since: operandMark),
        )
    }

    @inline(__always)
    private static func decodeSB(encoding: UInt32, address: UInt64) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .sb,
            category: .branchesExceptionSystem,
        )
    }

    @inline(__always)
    private static func decodeDSBnXS(encoding: UInt32, address: UInt64, CRm: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        switch CRm {
        case 2, 6, 10, 14:
            DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .dsb,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.unsignedImmediate(value: UInt64(CRm) | 0x10, width: 5)),
            )
        default:
            .undefined(at: address, encoding: encoding)
        }
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum ExceptionDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 2) & 0x7 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let op3 = UInt8((encoding >> 21) & 0x7)
        let LL = UInt8(encoding & 0x3)
        if op3 == 0b111, LL == 0b00 {
            return decodeTEnter(encoding: encoding, address: address, &sink)
        }
        let imm16 = UInt16((encoding >> 5) & 0xFFFF)
        let mnemonic: Mnemonic
        switch (op3, LL) {
        case (0b000, 0b01): mnemonic = .svc
        case (0b000, 0b10): mnemonic = .hvc
        case (0b000, 0b11): mnemonic = .smc
        case (0b001, 0b00): mnemonic = .brk
        case (0b010, 0b00): mnemonic = .hlt
        case (0b101, 0b01): mnemonic = .dcps1
        case (0b101, 0b10): mnemonic = .dcps2
        case (0b101, 0b11): mnemonic = .dcps3
        default:
            return .undefined(at: address, encoding: encoding)
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            branchClass: .exception,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.unsignedImmediate(value: UInt64(imm16), width: 16)),
        )
    }

    /// Apple TIndex `TENTER` — a 7-bit index in bits[11:5] and the `nb`
    /// suffix in bit 17; every other bit of the imm16 field must be zero.
    @inline(__always)
    private static func decodeTEnter(
        encoding: UInt32, address: UInt64, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let reserved: UInt32 = encoding & 0x001D_F000
        if reserved != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let index: UInt32 = (encoding >> 5) & 0x7F
        let noBranch: UInt32 = (encoding >> 17) & 1
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: noBranch == 0 ? .tenter : .tenterNb,
            branchClass: .exception,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.unsignedImmediate(value: UInt64(index), width: 7)),
        )
    }
}

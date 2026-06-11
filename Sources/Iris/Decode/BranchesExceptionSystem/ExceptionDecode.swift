// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Exception generation.
// Encoding: 1101 0100 op_high3 imm16 000 LL  (bits 4:2 = 000, bits 1:0 = LL)
// op_high3 ∈ {0,1,2,4,5} valid; {3,6,7} reserved → UNDEFINED.
// (op_high3, LL) → mnemonic:
//   (000, 01) SVC  (000, 10) HVC  (000, 11) SMC
//   (001, 00) BRK  (010, 00) HLT
//   (101, 01) DCPS1  (101, 10) DCPS2  (101, 11) DCPS3
// Any other (op_high3, LL) → UNDEFINED. imm16 carried as
// `.unsignedImmediate(value:, width: 16)`. ERET / ERETAA / ERETAB live in
// BranchRegDecode (different encoding family).

enum ExceptionDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bits 4:2 must be 000 for every encoding in this sub-class.
        if (encoding >> 2) & 0x7 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let op3 = UInt8((encoding >> 21) & 0x7)
        let LL = UInt8(encoding & 0x3)
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
            operands: [.unsignedImmediate(value: UInt64(imm16), width: 16)],
        )
    }
}

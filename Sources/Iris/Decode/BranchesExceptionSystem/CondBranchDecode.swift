// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Conditional branch (immediate).
// Encoding: 0101 0100 imm19 o0 cond
// o0 = 0 → B.cond. o0 = 1 → BC.cond (FEAT_HBC); both decode identically.
// imm19 is signed, scaled by 4. The conditional read of NZCV is modeled as
// flagEffect .readsNZCV (NZCV is not part of the GP/SIMD register-set).

enum CondBranchDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        // bits 31:24 are already known to be 0x54 by the family decoder.
        // o0 = 0 → B.cond; o0 = 1 → BC.cond (FEAT_HBC). Identical operand
        // shape; only the mnemonic differs.
        let o0 = UInt8((encoding >> 4) & 1)
        // `cond` is masked to four bits, and ConditionCode covers all 16
        // architectural encodings.
        let cond = ConditionCode(rawValue: UInt8(encoding & 0xF))!
        let imm19 = Int32(bitPattern: (encoding >> 5) & 0x7FFFF)
        let signed = (imm19 &<< 13) &>> 13
        let byteOffset = Int64(signed) &<< 2
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: o0 == 1 ? .bcCond : .bCond,
            branchClass: .conditional,
            flagEffect: .readsNZCV,
            category: .branchesExceptionSystem,
            operands: [.conditionCode(cond), .label(byteOffset: byteOffset)],
        )
    }
}

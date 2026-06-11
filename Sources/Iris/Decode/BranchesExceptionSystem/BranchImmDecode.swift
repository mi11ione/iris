// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Unconditional branch (immediate) decode.
// B  encoding: 0 00101 imm26
// BL encoding: 1 00101 imm26
// imm26 is signed, scaled by 4. BL writes X30 (LR); B writes nothing.
// PC-relative target resolution is left to consumers.

enum BranchImmDecode {
    @inline(__always)
    static func decodeB(encoding: UInt32, address: UInt64) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .b,
            branchClass: .direct,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: BranchImmDecode.signedOffset(encoding))],
        )
    }

    @inline(__always)
    static func decodeBL(encoding: UInt32, address: UInt64) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .bl,
            semanticWrites: RegisterSet.empty.inserting(.x(30)),
            branchClass: .call,
            category: .branchesExceptionSystem,
            operands: [.label(byteOffset: BranchImmDecode.signedOffset(encoding))],
        )
    }

    @inline(__always)
    private static func signedOffset(_ encoding: UInt32) -> Int64 {
        let raw = Int32(bitPattern: encoding & 0x03FF_FFFF)
        let signed = (raw &<< 6) &>> 6 // sign-extend 26 → 32
        return Int64(signed) &<< 2 // scale ×4
    }
}

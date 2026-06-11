// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Compare-and-branch (immediate).
// CBZ  encoding: sf 011010 0 imm19 Rt
// CBNZ encoding: sf 011010 1 imm19 Rt
// sf selects W (0) vs X (1). imm19 is signed, scaled by 4. Reads Rt;
// writes nothing. Branch class is .conditional.

enum CompareBranchDecode {
    @inline(__always)
    static func decode(encoding: UInt32, address: UInt64) -> DecodedDraft {
        let sf = UInt8((encoding >> 31) & 1)
        let op = UInt8((encoding >> 24) & 1)
        let imm19 = Int32(bitPattern: (encoding >> 5) & 0x7FFFF)
        let signed = (imm19 &<< 13) &>> 13 // sign-extend 19 → 32
        let byteOffset = Int64(signed) &<< 2
        let Rt = UInt8(encoding & 0x1F)
        let reg: RegisterRef = (sf == 1) ? .x(Rt) : .w(Rt)
        let mnemonic: Mnemonic = (op == 0) ? .cbz : .cbnz
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(reg),
            branchClass: .conditional,
            category: .branchesExceptionSystem,
            operands: [.register(reg), .label(byteOffset: byteOffset)],
        )
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FEAT_WFxT instructions (WFET / WFIT).
// Encoding: 1101 0101 0000 0011 0001 0000 op2 Rt
// op2 = 000 → WFET, 001 → WFIT. Other op2 → .undefined.
// CRm (bits 11:8) must be 0000.

enum WFXTDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, op2: UInt8, Rt: UInt8,
    ) -> DecodedDraft {
        let mnemonic: Mnemonic
        switch op2 {
        case 0b000: mnemonic = .wfet
        case 0b001: mnemonic = .wfit
        default:
            return .undefined(at: address, encoding: encoding)
        }
        let rtRef: RegisterRef = (Rt == 31) ? .xzr() : .x(Rt)
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: RegisterSet.empty.inserting(rtRef),
            category: .branchesExceptionSystem,
            operands: [.register(rtRef)],
        )
    }
}

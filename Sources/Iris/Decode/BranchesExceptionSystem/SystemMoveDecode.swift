// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MSR (register) / MRS.
// Encoding: 1101 0101 00 L 1 op0[1:0] op1 CRn CRm op2 Rt
// L = 0 → MSR (write Rt → sysreg). L = 1 → MRS (read sysreg → Rt).
// op0 is the 2-bit field at bits 20:19; op0 ∈ {0, 2, 3} reach here (op0 == 1
// is the SYS / SYSL class, dispatched separately).

enum SystemMoveDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, L: UInt8,
    ) -> DecodedDraft {
        let op0 = UInt8((encoding >> 19) & 0x3)
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let Rt = UInt8(encoding & 0x1F)
        let rtRef: RegisterRef = (Rt == 31) ? .xzr() : .x(Rt)
        let sysreg = SystemRegisterEncoding(
            op0: op0, op1: op1, crn: CRn, crm: CRm, op2: op2,
        )
        if L == 0 {
            // MSR — read Rt, write sysreg (sysreg writes not in the GP set).
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msr,
                semanticReads: RegisterSet.empty.inserting(rtRef),
                category: .branchesExceptionSystem,
                operands: [.systemRegister(sysreg), .register(rtRef)],
            )
        }
        // MRS — write Rt, read sysreg (sysreg reads not in the GP set).
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .mrs,
            semanticWrites: RegisterSet.empty.inserting(rtRef),
            category: .branchesExceptionSystem,
            operands: [.register(rtRef), .systemRegister(sysreg)],
        )
    }

    /// FEAT_D128 MRRS (L=1) / MSRR (L=0) — 128-bit system-register move to/
    /// from a consecutive even/odd X-register pair (Xt, Xt+1). Rt must be
    /// even (Rt<0> == 1 is UNDEFINED). op0 = 2 + o0 (o0 = bit 19).
    @inline(__always)
    static func decodeD128(
        encoding: UInt32, address: UInt64, L: UInt8,
    ) -> DecodedDraft {
        let Rt = UInt8(encoding & 0x1F)
        if Rt & 1 != 0 {
            return .undefined(at: address, encoding: encoding)
        }
        let op0 = UInt8((encoding >> 19) & 0x3)
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let rt1: RegisterRef = .x(Rt)
        let rt2: RegisterRef = .x(Rt &+ 1)
        let pair = RegisterSet.empty.inserting(rt1).inserting(rt2)
        let sysreg = SystemRegisterEncoding(
            op0: op0, op1: op1, crn: CRn, crm: CRm, op2: op2,
        )
        if L == 0 {
            // MSRR — read the pair, write sysreg.
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msrr,
                semanticReads: pair,
                category: .branchesExceptionSystem,
                operands: [.systemRegister(sysreg), .register(rt1), .register(rt2)],
            )
        }
        // MRRS — write the pair, read sysreg.
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .mrrs,
            semanticWrites: pair,
            category: .branchesExceptionSystem,
            operands: [.register(rt1), .register(rt2), .systemRegister(sysreg)],
        )
    }
}

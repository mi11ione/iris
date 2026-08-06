// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum SystemMoveDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, L: UInt8, _ sink: inout OperandSink,
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
        let isNZCV = SystemMoveDecode.isNZCV(sysreg)
        if L == 0 {
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msr,
                semanticReads: RegisterSet.empty.inserting(rtRef),
                flagEffect: isNZCV ? .nzcv : .none,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.systemRegister(sysreg), .register(rtRef)),
            )
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .mrs,
            semanticWrites: RegisterSet.empty.inserting(rtRef),
            flagEffect: isNZCV ? .readsNZCV : .none,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(rtRef), .systemRegister(sysreg)),
        )
    }

    /// Whether the encoding names PSTATE's `NZCV` — the one system register
    /// whose transfer is a condition-flag transfer.
    @inline(__always)
    @_effects(readonly)
    static func isNZCV(_ s: SystemRegisterEncoding) -> Bool {
        s.op0 == 3 && s.op1 == 3 && s.crn == 4 && s.crm == 2 && s.op2 == 0
    }

    /// FEAT_D128 MRRS (L=1) / MSRR (L=0).
    @inline(__always)
    static func decodeD128(
        encoding: UInt32, address: UInt64, L: UInt8, _ sink: inout OperandSink,
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
            return DecodedDraft(
                address: address,
                encoding: encoding,
                mnemonic: .msrr,
                semanticReads: pair,
                category: .branchesExceptionSystem,
                operandCount: sink.emit(.systemRegister(sysreg), .register(rt1), .register(rt2)),
            )
        }
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .mrrs,
            semanticWrites: pair,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.register(rt1), .register(rt2), .systemRegister(sysreg)),
        )
    }
}

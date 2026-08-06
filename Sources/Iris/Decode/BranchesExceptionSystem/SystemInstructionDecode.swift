// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum SystemInstructionDecode {
    @inline(__always)
    static func decode(
        encoding: UInt32, address: UInt64, L: UInt8, Rt: UInt8, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        let rtRef: RegisterRef = (Rt == 31) ? .xzr() : .x(Rt)
        let mnemonic: Mnemonic = (L == 0) ? .sys : .sysl
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let alias = (L == 0)
            ? BESSysAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
            : BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2)
        let sysTouchesRt = alias.map { $0.touchesRt(Rt) } ?? (Rt != 31)
        let syslTouchesRt = alias.map { $0.touchesRt(Rt) } ?? true
        let reads: RegisterSet = (L == 0 && sysTouchesRt)
            ? RegisterSet.empty.inserting(rtRef)
            : .empty
        let writes: RegisterSet = (L == 1 && syslTouchesRt)
            ? RegisterSet.empty.inserting(rtRef)
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: mnemonic,
            semanticReads: reads,
            semanticWrites: writes,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.systemOp(SystemOp(rawEncoding: encoding))),
        )
    }

    /// FEAT_D128 SYSP — 128-bit SYS pair. Rt must be even or 31. Reads the
    /// (Rt, Rt+1) pair when a TLBIP alias matches or when Rt != 31; a generic
    /// SYSP at Rt == 31 reads nothing.
    @inline(__always)
    static func decodeSysp(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let Rt = UInt8(encoding & 0x1F)
        if Rt & 1 != 0, Rt != 31 {
            return .undefined(at: address, encoding: encoding)
        }
        let op1 = UInt8((encoding >> 16) & 0x7)
        let CRn = UInt8((encoding >> 12) & 0xF)
        let CRm = UInt8((encoding >> 8) & 0xF)
        let op2 = UInt8((encoding >> 5) & 0x7)
        let aliased = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) != nil
        let readsPair = aliased || Rt != 31
        let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
        let reads: RegisterSet = readsPair
            ? RegisterSet.empty.inserting(.x(Rt)).inserting(.x(rt2))
            : .empty
        return DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .sysp,
            semanticReads: reads,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(.systemOp(SystemOp(rawEncoding: encoding))),
        )
    }
}

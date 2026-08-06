// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

extension SVEPredicateControlDecode {
    @inline(__always)
    static func decodePredicateCount(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 19) & 1 == 0 {
            return decodeCntp(e, a, &sink)
        }
        switch (e >> 11) & 0b11 {
        case 0b00: return decodeCountPredicate(e, a, scalar: false, &sink)
        case 0b01: return decodeCountPredicate(e, a, scalar: true, &sink)
        default: return decodeFfrWrite(e, a, &sink)
        }
    }

    @inline(__always)
    static func decodeCntp(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = elementSize(e >> 22)
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .cntp,
            semanticWrites: gpr64Mask(rd), category: .sve,
            operandCount: sink.emit(.register(gpr64(rd)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: sz))),
            scalableReads: predSet(pg).insertingPredicate(pn),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// INCP/DECP/SQINCP/UQINCP/SQDECP/UQDECP — scalar (`scalar==true`) or
    /// vector. `op = b18:16`; the predicate `Pm` (b8:5) is a data SOURCE.
    @inline(__always)
    static func decodeCountPredicate(_ e: UInt32, _ a: UInt64, scalar: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 9) & 1 != 0 { return undefined(e, a) }
        let op = (e >> 16) & 0b111
        if op > 0b101 { return undefined(e, a) }
        let sz = elementSize(e >> 22)
        let pm = UInt8((e >> 5) & 0xF)
        let dn = UInt8(e & 0x1F)
        let pmOp = Operand.scalablePredicate(ScalablePredicateRef(registerIndex: pm, element: sz))
        let pmReads = predSet(pm)
        if !scalar {
            if (e >> 22) & 0b11 == 0 || (e >> 10) & 1 != 0 { return undefined(e, a) }
            let mnemonic = countPredicateVectorMnemonic(op)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: vecMask(dn), semanticWrites: vecMask(dn), category: .sve,
                operandCount: sink.emit(.scalableVector(ScalableVectorRef(registerIndex: dn, element: sz)), pmOp),
                scalableReads: pmReads, scalableEffect: .readsStreamingMode,
            )
        }
        if op >= 0b100 {
            if (e >> 10) & 1 != 0 { return undefined(e, a) }
            let mnemonic: Mnemonic = op == 0b100 ? .incp : .decp
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: gpr64Mask(dn), semanticWrites: gpr64Mask(dn), category: .sve,
                operandCount: sink.emit(.register(gpr64(dn)), pmOp),
                scalableReads: pmReads, scalableEffect: .readsStreamingMode,
            )
        }
        let is64 = (e >> 10) & 1 == 1
        let mnemonic = countPredicateSatMnemonic(op)
        let mask = gpr64Mask(dn)
        let signed = op & 1 == 0
        let dest: Operand = (!is64 && !signed) ? .register(gpr32(dn)) : .register(gpr64(dn))
        let operandCount: UInt8 = (!is64 && signed)
            ? sink.emit(dest, pmOp, .register(gpr32(dn)))
            : sink.emit(dest, pmOp)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: mask, semanticWrites: mask, category: .sve,
            operandCount: operandCount, scalableReads: pmReads,
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func countPredicateVectorMnemonic(_ op: UInt32) -> Mnemonic {
        switch op {
        case 0b000: .sqincp
        case 0b001: .uqincp
        case 0b010: .sqdecp
        case 0b011: .uqdecp
        case 0b100: .incp
        default: .decp
        }
    }

    @inline(__always)
    static func countPredicateSatMnemonic(_ op: UInt32) -> Mnemonic {
        switch op {
        case 0b000: .sqincp
        case 0b001: .uqincp
        case 0b010: .sqdecp
        default: .uqdecp
        }
    }

    @inline(__always)
    static func decodeFfrWrite(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 22) & 0b11 != 0 || (e >> 16) & 0b11 != 0 || (e >> 9) & 0b11 != 0 || (e & 0x1F) != 0 {
            return undefined(e, a)
        }
        if (e >> 18) & 1 == 1 {
            if (e >> 5) & 0xF != 0 { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .setffr, category: .sve,
                scalableWrites: ScalableRegisterSet.empty.insertingFFR(),
                scalableEffect: .readsStreamingMode,
            )
        }
        let pn = UInt8((e >> 5) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .wrffr, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pn),
            scalableWrites: ScalableRegisterSet.empty.insertingFFR(),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeWhileTerm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 13) & 1 == 0 {
            return decodeWhile(e, a, &sink)
        }
        let b12_10 = (e >> 10) & 0b111
        if b12_10 == 0b000 {
            return decodeCterm(e, a, &sink)
        }
        return decodeWhileRwWr(e, a, &sink)
    }

    @inline(__always)
    static func decodeWhile(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = elementSize(e >> 22)
        let sf = (e >> 12) & 1
        let cc = (((e >> 11) & 1) << 2) | (((e >> 10) & 1) << 1) | ((e >> 4) & 1)
        let rm = UInt8((e >> 16) & 0x1F)
        let rn = UInt8((e >> 5) & 0x1F)
        let pd = UInt8(e & 0xF)
        let mnemonic = whileMnemonic(cc)
        let reads = sf == 1
            ? gpr64Mask(rn).union(gpr64Mask(rm))
            : gpr32Mask(rn).union(gpr32Mask(rm))
        let rnOp: Operand = sf == 1 ? .register(gpr64(rn)) : .register(gpr32(rn))
        let rmOp: Operand = sf == 1 ? .register(gpr64(rm)) : .register(gpr32(rm))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic, semanticReads: reads,
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: sz, role: .result)), rnOp, rmOp),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func whileMnemonic(_ cc: UInt32) -> Mnemonic {
        switch cc {
        case 0b000: .whilege
        case 0b001: .whilegt
        case 0b010: .whilelt
        case 0b011: .whilele
        case 0b100: .whilehs
        case 0b101: .whilehi
        case 0b110: .whilelo
        default: .whilels
        }
    }

    @inline(__always)
    static func decodeWhileRwWr(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = elementSize(e >> 22)
        let rm = UInt8((e >> 16) & 0x1F)
        let rn = UInt8((e >> 5) & 0x1F)
        let pd = UInt8(e & 0xF)
        let mnemonic: Mnemonic = (e >> 4) & 1 == 1 ? .whilerw : .whilewr
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: gpr64Mask(rn).union(gpr64Mask(rm)),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: sz, role: .result)), .register(gpr64(rn)), .register(gpr64(rm))),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCterm(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 23) & 1 != 1 || (e & 0xF) != 0 { return undefined(e, a) }
        let is64 = (e >> 22) & 1 == 1
        let rm = UInt8((e >> 16) & 0x1F)
        let rn = UInt8((e >> 5) & 0x1F)
        let mnemonic: Mnemonic = (e >> 4) & 1 == 1 ? .ctermne : .ctermeq
        let reads = is64
            ? gpr64Mask(rn).union(gpr64Mask(rm))
            : gpr32Mask(rn).union(gpr32Mask(rm))
        let rnOp: Operand = is64 ? .register(gpr64(rn)) : .register(gpr32(rn))
        let rmOp: Operand = is64 ? .register(gpr64(rm)) : .register(gpr32(rm))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic, semanticReads: reads,
            flagEffect: [.writesN, .writesV, .readsC], category: .sve,
            operandCount: sink.emit(rnOp, rmOp),
        )
    }

    /// A GPR64 ref where index 31 is XZR (so `insertingNonZero`/`gpr64Mask`
    /// drop it.
    @inline(__always)
    static func gpr64(_ n: UInt8) -> RegisterRef {
        n & 0x1F == 31 ? .xzr() : .x(n & 0x1F)
    }

    @inline(__always)
    static func gpr32(_ n: UInt8) -> RegisterRef {
        n & 0x1F == 31 ? .wzr() : .w(n & 0x1F)
    }

    /// Canonical-index bitmask for a GPR64 operand, XZR dropped.
    @inline(__always)
    static func gpr64Mask(_ n: UInt8) -> RegisterSet {
        n & 0x1F == 31 ? .empty : RegisterSet.empty.inserting(.x(n & 0x1F))
    }

    @inline(__always)
    static func gpr32Mask(_ n: UInt8) -> RegisterSet {
        n & 0x1F == 31 ? .empty : RegisterSet.empty.inserting(.w(n & 0x1F))
    }

    /// Canonical-index bitmask for a Z_n operand (bit 32+n, shared with V_n).
    @inline(__always)
    static func vecMask(_ n: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(ScalableVectorRef(registerIndex: n))
    }
}

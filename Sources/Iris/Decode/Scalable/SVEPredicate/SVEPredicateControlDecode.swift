// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The SVE predicate-and-control decoder for SVE-predicate.
enum SVEPredicateControlDecode {
    /// Decode an in-scope SVE predicate/control word.
    @_optimize(speed)
    static func decode(encoding: UInt32, address: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (encoding >> 24) & 0xFF == 0x25 {
            return decodePredicateRegion(encoding: encoding, address: address, &sink)
        }
        return decodeIntegerRegion(encoding: encoding, address: address, &sink)
    }

    /// 0x25 region sub-dispatch (G1–G6).
    @inline(__always)
    static func decodePredicateRegion(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let b21 = (e >> 21) & 1
        let b15_14 = (e >> 14) & 0b11
        if b21 == 0 {
            switch b15_14 {
            case 0b01:
                if (e >> 20) & 1 == 0 {
                    return decodePredicateLogical(e, a, &sink)
                }
                return decodeBreak(e, a, &sink)
            default:
                if (e >> 20) & 1 == 0 {
                    return decodeBreakPair(e, a, &sink)
                }
                if (e >> 19) & 1 == 0 {
                    return decodePtest(e, a, &sink)
                }
                return decodePredicateMisc(e, a, &sink)
            }
        }
        switch b15_14 {
        case 0b00:
            return decodeWhileTerm(e, a, &sink)
        default:
            return decodePredicateCount(e, a, &sink)
        }
    }

    @inline(__always)
    static func decodePredicateMisc(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let b15_10 = (e >> 10) & 0b111111
        if b15_10 == 0b111000 {
            return decodePtrue(e, a, &sink)
        }
        if b15_10 == 0b111001 {
            return decodePfalse(e, a, &sink)
        }
        if b15_10 == 0b111100 {
            return decodeRdffr(e, a, &sink)
        }
        return decodeFirstNext(e, a, &sink)
    }

    @inline(__always)
    static func decodePtrue(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 17) & 0b11 != 0 || (e >> 4) & 1 != 0 { return undefined(e, a) }
        let s = (e >> 16) & 1
        let sz = elementSize(e >> 22)
        let pd = UInt8(e & 0xF)
        let pat = UInt8((e >> 5) & 0b11111)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: s == 1 ? .ptrues : .ptrue,
            flagEffect: s == 1 ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: sz, role: .result)), .svePredicatePattern(SVEPredicatePattern(raw: pat))),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodePfalse(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 22) & 0b11 != 0 || (e >> 16) & 0b111 != 0
            || (e >> 9) & 1 != 0 || (e >> 4) & 0b11111 != 0
        {
            return undefined(e, a)
        }
        let pd = UInt8(e & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .pfalse, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result))),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodePtest(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 22) & 0b11 != 0b01 || (e >> 16) & 0b111 != 0
            || (e >> 9) & 1 != 0 || (e & 0b11111) != 0
        {
            return undefined(e, a)
        }
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .ptest,
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodePredicateLogical(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opcBits: UInt32 = (((e >> 23) & 1) << 3) | (((e >> 22) & 1) << 2) | (((e >> 9) & 1) << 1) | ((e >> 4) & 1)
        let opc = UInt8(opcBits)
        if opc == 0b0111 { return undefined(e, a) }
        let pm = UInt8((e >> 16) & 0xF)
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let pd = UInt8(e & 0xF)
        let setsFlags = (e >> 22) & 1 == 1
        switch opc {
        case 0b1000, 0b1100:
            if pg == pn, pn == pm {
                return movAlias2(e, a, mnemonic: setsFlags ? .movs : .mov, pd: pd, pn: pn, setsFlags: setsFlags, &sink)
            }
        case 0b0000, 0b0100:
            if pm == pn {
                return movAlias3z(e, a, mnemonic: setsFlags ? .movs : .mov, pd: pd, pg: pg, pn: pn, setsFlags: setsFlags, &sink)
            }
        case 0b0011:
            if pm == pd {
                return movAliasM(e, a, pd: pd, pg: pg, pn: pn, &sink)
            }
        case 0b0010, 0b0110:
            if pm == pg {
                return notAlias(e, a, mnemonic: setsFlags ? .nots : .not, pd: pd, pg: pg, pn: pn, setsFlags: setsFlags, &sink)
            }
        default:
            break
        }
        let mnemonic = predicateLogicalBase(opc)
        let isSel = opc == 0b0011
        let pgRef = isSel
            ? ScalablePredicateRef(registerIndex: pg, role: .governing)
            : ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: setsFlags ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(pgRef), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b)), .scalablePredicate(ScalablePredicateRef(registerIndex: pm, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn).insertingPredicate(pm),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    /// `MOV <Pd>.B, <Pn>.B` (from ORR) / `MOVS …` (from ORRS).
    @inline(__always)
    static func movAlias2(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, pd: UInt8, pn: UInt8, setsFlags: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: setsFlags ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pn), scalableWrites: predSet(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `MOV <Pd>.B, <Pg>/Z, <Pn>.B` (from AND) / `MOVS …` (from ANDS).
    @inline(__always)
    static func movAlias3z(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, pd: UInt8, pg: UInt8, pn: UInt8, setsFlags: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: setsFlags ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn), scalableWrites: predSet(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `MOV <Pd>.B, <Pg>/M, <Pn>.B` (from SEL, Pm==Pd).
    @inline(__always)
    static func movAliasM(_ e: UInt32, _ a: UInt64, pd: UInt8, pg: UInt8, pn: UInt8, _ sink: inout OperandSink) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: .mov, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .merging, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn).insertingPredicate(pd),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    /// `NOT <Pd>.B, <Pg>/Z, <Pn>.B` (from EOR, Pm==Pg) / `NOTS …` (from EORS).
    @inline(__always)
    static func notAlias(
        _ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, pd: UInt8, pg: UInt8, pn: UInt8, setsFlags: Bool, _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: setsFlags ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn), scalableWrites: predSet(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func predicateLogicalBase(_ opc: UInt8) -> Mnemonic {
        switch opc {
        case 0b0000: .and
        case 0b0001: .bic
        case 0b0010: .eor
        case 0b0011: .sel
        case 0b0100: .ands
        case 0b0101: .bics
        case 0b0110: .eors
        case 0b1000: .orr
        case 0b1001: .orn
        case 0b1010: .nor
        case 0b1011: .nand
        case 0b1100: .orrs
        case 0b1101: .orns
        case 0b1110: .nors
        default: .nands
        }
    }

    @inline(__always)
    static func decodeBreak(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 16) & 0b111 != 0 || (e >> 9) & 1 != 0 { return undefined(e, a) }
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let pd = UInt8(e & 0xF)
        if (e >> 19) & 1 == 1 {
            if (e >> 23) & 1 != 0 || (e >> 4) & 1 != 0 { return undefined(e, a) }
            let s = (e >> 22) & 1
            return DecodedDraft(
                address: a, encoding: e, mnemonic: s == 1 ? .brkns : .brkn,
                flagEffect: s == 1 ? .nzcv : .none, category: .sve,
                operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b)), .scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b))),
                scalableReads: predSet(pg).insertingPredicate(pn).insertingPredicate(pd),
                scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
            )
        }
        let b = (e >> 23) & 1
        let s = (e >> 22) & 1
        let m = (e >> 4) & 1
        if s == 1, m == 1 { return undefined(e, a) }
        let merging = m == 1
        let mnemonic: Mnemonic = b == 1 ? (s == 1 ? .brkbs : .brkb) : (s == 1 ? .brkas : .brka)
        var reads = predSet(pg).insertingPredicate(pn)
        var effect: ScalableEffect = .readsStreamingMode
        if merging {
            reads = reads.insertingPredicate(pd)
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: s == 1 ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: merging ? .merging : .zeroing, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))),
            scalableReads: reads, scalableWrites: predSet(pd), scalableEffect: effect,
        )
    }

    @inline(__always)
    static func decodeBreakPair(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 23) & 1 != 0 || (e >> 9) & 1 != 0 { return undefined(e, a) }
        let s = (e >> 22) & 1
        let op = (e >> 4) & 1
        let pm = UInt8((e >> 16) & 0xF)
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let pd = UInt8(e & 0xF)
        let mnemonic: Mnemonic = op == 1 ? (s == 1 ? .brkpbs : .brkpb) : (s == 1 ? .brkpas : .brkpa)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            flagEffect: s == 1 ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b)), .scalablePredicate(ScalablePredicateRef(registerIndex: pm, element: .b))),
            scalableReads: predSet(pg).insertingPredicate(pn).insertingPredicate(pm),
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeFirstNext(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 4) & 1 != 0 { return undefined(e, a) }
        let opcHi = (e >> 16) & 0b111
        let opcLo = (e >> 9) & 0b11
        let pg = UInt8((e >> 5) & 0xF)
        let pdn = UInt8(e & 0xF)
        if opcHi == 0b000, opcLo == 0b00 {
            if (e >> 22) & 0b11 != 0b01 { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .pfirst, flagEffect: .nzcv, category: .sve,
                operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: .b))),
                scalableReads: predSet(pg).insertingPredicate(pdn), scalableWrites: predSet(pdn),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        if opcHi == 0b001, opcLo == 0b10 {
            let sz = elementSize(e >> 22)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .pnext, flagEffect: .nzcv, category: .sve,
                operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: sz, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: sz))),
                scalableReads: predSet(pg).insertingPredicate(pdn), scalableWrites: predSet(pdn),
                scalableEffect: .readsStreamingMode,
            )
        }
        return undefined(e, a)
    }

    @inline(__always)
    static func decodeRdffr(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 23) & 1 != 0 || (e >> 17) & 0b11 != 0
            || (e >> 9) & 1 != 0 || (e >> 4) & 1 != 0
        {
            return undefined(e, a)
        }
        let unpred = (e >> 16) & 1 == 1
        let s = (e >> 22) & 1
        if s == 1, unpred { return undefined(e, a) }
        let pd = UInt8(e & 0xF)
        if unpred {
            if (e >> 5) & 0xF != 0 { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .rdffr, category: .sve,
                operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result))),
                scalableReads: ScalableRegisterSet.empty.insertingFFR(),
                scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
            )
        }
        let pg = UInt8((e >> 5) & 0xF)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: s == 1 ? .rdffrs : .rdffr,
            flagEffect: s == 1 ? .nzcv : .none, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: .zeroing, role: .governing))),
            scalableReads: predSet(pg).insertingFFR(), scalableWrites: predSet(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// Element size from a 2-bit `sz` field (masked).
    @inline(__always)
    static func elementSize(_ sz: UInt32) -> ScalarSize {
        switch sz & 0b11 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    /// A predicate read/write set containing just `index`.
    @inline(__always)
    static func predSet(_ index: UInt8) -> ScalableRegisterSet {
        ScalableRegisterSet.empty.insertingPredicate(index)
    }

    /// Well-formed in-scope UNDEFINED (`category = .sve`, raw encoding kept).
    @inline(__always)
    static func undefined(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}

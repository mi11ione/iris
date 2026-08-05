// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE predicate & control decoder. Entry + top sub-dispatch
// , plus the 0x25-region predicate-producing groups:
// G1 initialise/test, G2 logical (+ the 7 disassembler-visible aliases),
// G3 break/partition, G4 first-fault register. G5/G6 (count, WHILE/CTERM)
// and G7-G9 (element-count/adjust, INDEX, MOVPRFX) are in sibling files.
//
// Called only from `SVEDecoder.decode` when `isSVEPredicateControlEncoding`
// holds, so `decode` is a total function over SVE-predicate's domain: every path
// returns a real record or a well-formed UNDEFINED (`.undefined`, `.sve`)
// for the genuine in-scope holes (opc4=0111, BRKAS/BRKBS with /m, …).

/// The SVE predicate-and-control decoder for SVE-predicate.
enum SVEPredicateControlDecode {
    /// Decode an in-scope SVE predicate/control word. Precondition (by
    /// construction, not asserted): `isSVEPredicateControlEncoding(encoding)`.
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
                return decodeBreak(e, a, &sink) // BRKA/BRKB (b19=0) or BRKN (b19=1)
            // b15:14==11. The scope predicate admits only 01 above and 11 here
            // when b21==0 (00/10 are integer-compare-to-predicate, out of
            // scope), so the dispatch needs no unreachable UNDEFINED arm.
            default:
                if (e >> 20) & 1 == 0 {
                    return decodeBreakPair(e, a, &sink) // BRKPA/BRKPB
                }
                if (e >> 19) & 1 == 0 {
                    return decodePtest(e, a, &sink)
                }
                return decodePredicateMisc(e, a, &sink) // PTRUE(S)/PFALSE/RDFFR/PFIRST/PNEXT
            }
        }
        switch b15_14 {
        case 0b00:
            return decodeWhileTerm(e, a, &sink) // G6
        // b15:14==10. The scope predicate admits only 00 above and 10 here when
        // b21==1 (01/11 are PSEL/PEXT/WHILE-counter and wide-/FP-immediate, out
        // of scope), so the dispatch needs no unreachable UNDEFINED arm.
        default:
            return decodePredicateCount(e, a, &sink) // G5 + WRFFR/SETFFR
        }
    }

    // MARK: G1 — PTRUE / PTRUES / PFALSE / PTEST

    @inline(__always)
    static func decodePredicateMisc(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let b15_10 = (e >> 10) & 0b111111
        if b15_10 == 0b111000 {
            return decodePtrue(e, a, &sink) // PTRUE / PTRUES
        }
        if b15_10 == 0b111001 {
            return decodePfalse(e, a, &sink)
        }
        if b15_10 == 0b111100 {
            return decodeRdffr(e, a, &sink) // G4 predicated/unpredicated RDFFR
        }
        // bits[15:11] == 11000 — PFIRST / PNEXT. The scope predicate admits only
        // the three bits[15:10] values above and this pattern in the
        // predicate-misc sub-region, so no UNDEFINED tail is reachable.
        return decodeFirstNext(e, a, &sink)
    }

    @inline(__always)
    static func decodePtrue(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b18:17 must be 0, b4 must be 0.
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
        // b23:22, b18:16, b9, b8:4 all zero.
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
        // sz(b23:22)==01, b18:16==0, b9==0, b4:0==0.
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

    // MARK: G2 — Predicate logical (+ the 7 aliases)

    @inline(__always)
    static func decodePredicateLogical(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let opcBits: UInt32 = (((e >> 23) & 1) << 3) | (((e >> 22) & 1) << 2) | (((e >> 9) & 1) << 1) | ((e >> 4) & 1)
        let opc = UInt8(opcBits)
        if opc == 0b0111 { return undefined(e, a) } // SELS slot, unallocated
        let pm = UInt8((e >> 16) & 0xF)
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let pd = UInt8(e & 0xF)
        let setsFlags = (e >> 22) & 1 == 1
        // Alias resolution (decode-side). opc4 pins the base; ≤1 alias each.
        switch opc {
        case 0b1000, 0b1100: // ORR / ORRS → MOV/MOVS when Pg==Pn==Pm
            if pg == pn, pn == pm {
                return movAlias2(e, a, mnemonic: setsFlags ? .movs : .mov, pd: pd, pn: pn, setsFlags: setsFlags, &sink)
            }
        case 0b0000, 0b0100: // AND / ANDS → MOV/MOVS when Pm==Pn
            if pm == pn {
                return movAlias3z(e, a, mnemonic: setsFlags ? .movs : .mov, pd: pd, pg: pg, pn: pn, setsFlags: setsFlags, &sink)
            }
        case 0b0011: // SEL → MOV/M when Pm==Pd
            if pm == pd {
                return movAliasM(e, a, pd: pd, pg: pg, pn: pn, &sink)
            }
        case 0b0010, 0b0110: // EOR / EORS → NOT/NOTS when Pm==Pg
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

    /// `MOV <Pd>.B, <Pn>.B` (from ORR) / `MOVS …` (from ORRS): 2-operand.
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

    /// `MOV <Pd>.B, <Pg>/Z, <Pn>.B` (from AND) / `MOVS …` (from ANDS): 3-operand /z.
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

    /// `MOV <Pd>.B, <Pg>/M, <Pn>.B` (from SEL, Pm==Pd): reads Pd (as Pm source),
    /// FULL write of Pd — partialWrite stays CLEAR despite the /M token.
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
        default: .nands // 0b1111
        }
    }

    // MARK: G3 — Break / partition

    @inline(__always)
    static func decodeBreak(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b19 discriminates BRKA/BRKB (0) from BRKN (1). b18:16==0, b9==0.
        if (e >> 16) & 0b111 != 0 || (e >> 9) & 1 != 0 { return undefined(e, a) }
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let pd = UInt8(e & 0xF)
        if (e >> 19) & 1 == 1 {
            // BRKN / BRKNS: b23==0, b4==0. Pdm tied (read + write); partialWrite CLEAR.
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
        // BRKA / BRKB: B=b23, S=b22, M=b4. S&&M is UNDEFINED.
        let b = (e >> 23) & 1
        let s = (e >> 22) & 1
        let m = (e >> 4) & 1
        if s == 1, m == 1 { return undefined(e, a) }
        let merging = m == 1
        let mnemonic: Mnemonic = b == 1 ? (s == 1 ? .brkbs : .brkb) : (s == 1 ? .brkas : .brka)
        var reads = predSet(pg).insertingPredicate(pn)
        var effect: ScalableEffect = .readsStreamingMode
        if merging {
            reads = reads.insertingPredicate(pd) // /M reads Pd (RMW)
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
        // BRKPA/BRKPB (+S). b23==0, b9==0. S=b22, op=b4.
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
        // opc {b18:16, b10:9}: 00000 PFIRST (sz fixed 01), 00110 PNEXT. b4==0.
        if (e >> 4) & 1 != 0 { return undefined(e, a) }
        let opcHi = (e >> 16) & 0b111
        let opcLo = (e >> 9) & 0b11
        let pg = UInt8((e >> 5) & 0xF)
        let pdn = UInt8(e & 0xF)
        if opcHi == 0b000, opcLo == 0b00 {
            // PFIRST: sz must be 01 (opcode, not size); .B only. Pdn RMW, partialWrite SET.
            if (e >> 22) & 0b11 != 0b01 { return undefined(e, a) }
            return DecodedDraft(
                address: a, encoding: e, mnemonic: .pfirst, flagEffect: .nzcv, category: .sve,
                operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: .b, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)), .scalablePredicate(ScalablePredicateRef(registerIndex: pdn, element: .b))),
                scalableReads: predSet(pg).insertingPredicate(pdn), scalableWrites: predSet(pdn),
                scalableEffect: [.readsStreamingMode, .partialWrite],
            )
        }
        if opcHi == 0b001, opcLo == 0b10 {
            // PNEXT: all sizes. Pdn read (ungated) but seeded-from-zero → full write, partialWrite CLEAR.
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

    // MARK: G4 — First-fault register (RDFFR; WRFFR/SETFFR are in the count file)

    @inline(__always)
    static func decodeRdffr(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b16: 0 predicated, 1 unpredicated. S=b22. S&&unpred UNDEFINED.
        // Fixed SBZ bits (mask 0xFFFFFE10 / 0xFFFFFFF0): b23, b18:17, b9, b4 = 0.
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
            // b8:5 must be 0.
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

    // MARK: shared builders

    /// Element size from a 2-bit `sz` field (masked): 0→B, 1→H, 2→S, 3→D.
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

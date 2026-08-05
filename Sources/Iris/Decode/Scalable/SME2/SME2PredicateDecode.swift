// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SVE-region predicate-as-counter carve (op0=0b0010,
// top byte 0x25, b21=1): WHILE producing a counter predicate (PN8-PN15,
// mandatory vlx2/vlx4) or a predicate pair ({P2d, P2d+1}), PEXT (single and
// mod-16-wrapping pair), PTRUE-counter, CNTP-counter (PN0-PN15 source),
// FIRSTP/LASTP, and PSEL (tsz trailing-one size/index scheme; tsz=0000 is
// reserved). The eight iclass families are mutually disjoint under their
// structural masks, so match order is immaterial; every unmatched carve word
// is a claimed hole (UNDEFINED, category `.sve` — the carve stays in the SVE
// family's identity per the scalable core routing).

/// The SME2 predicate-as-counter decoder for SME2 (op0=2 carve).
enum SME2PredicateDecode {
    /// Decode an in-scope carve word. Precondition (by construction, not
    /// asserted): `isSVECounterPredicateEncoding(e)`.
    @_optimize(speed)
    static func decode(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if e & 0xFF20_D010 == 0x2520_4010 { return decodeWhileCounter(e, a, &sink) }
        if e & 0xFF20_F010 == 0x2520_5010 { return decodeWhilePair(e, a, &sink) }
        if e & 0xFF3F_FC10 == 0x2520_7010 { return decodePext(e, a, pair: false, &sink) }
        if e & 0xFF3F_FE10 == 0x2520_7410 { return decodePext(e, a, pair: true, &sink) }
        if e & 0xFF3F_FFF8 == 0x2520_7810 { return decodePtrueCounter(e, a, &sink) }
        if e & 0xFF3F_FA00 == 0x2520_8200 { return decodeCntpCounter(e, a, &sink) }
        if e & 0xFF3F_C200 == 0x2521_8000 { return decodeFirstLastP(e, a, mnemonic: .firstp, &sink) }
        if e & 0xFF3F_C200 == 0x2522_8000 { return decodeFirstLastP(e, a, mnemonic: .lastp, &sink) }
        if e & 0xFF20_C210 == 0x2520_4000 { return decodePsel(e, a, &sink) }
        return undefinedSVE(e, a)
    }

    // MARK: - families

    /// `WHILE<cc> PNd.<T>, Xn, Xm, vlx<2|4>` — counter destination, NZCV.
    @inline(__always)
    private static func decodeWhileCounter(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let element = sizeElement(e)
        let pnd = 8 &+ UInt8(e & 0x7)
        let rn = UInt8((e >> 5) & 0x1F)
        let rm = UInt8((e >> 16) & 0x1F)
        let multiplier: UInt8 = e & 0x2000 != 0 ? 4 : 2
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: whileMnemonic(unsigned: e & 0x800 != 0, less: e & 0x400 != 0, orEqual: e & 0x8 != 0),
            semanticReads: SME2Decode.dataMask(rn).union(SME2Decode.dataMask(rm)),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(
                registerIndex: pnd, element: element, role: .result, isCounter: true,
            )), gprOperand(rn), gprOperand(rm), .vectorLengthMultiplier(multiplier)),
            scalableWrites: SME2Decode.predMask(pnd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `WHILE<cc> { P2d.<T>, P2d+1.<T> }, Xn, Xm` — even/odd pair, NZCV.
    @inline(__always)
    private static func decodeWhilePair(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let element = sizeElement(e)
        let first = UInt8(e & 0xE) // Pd<<1
        let rn = UInt8((e >> 5) & 0x1F)
        let rm = UInt8((e >> 16) & 0x1F)
        return DecodedDraft(
            address: a, encoding: e,
            mnemonic: whileMnemonic(unsigned: e & 0x800 != 0, less: e & 0x400 != 0, orEqual: e & 0x1 != 0),
            semanticReads: SME2Decode.dataMask(rn).union(SME2Decode.dataMask(rm)),
            flagEffect: .nzcv, category: .sve,
            operandCount: sink.emit(.predicateGroup(firstIndex: first, count: 2, element: element), gprOperand(rn), gprOperand(rm)),
            scalableWrites: SME2Decode.predMask(first).union(SME2Decode.predMask(first &+ 1)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `PEXT Pd.<T>, PNn[i]` / `PEXT { Pd.<T>, P(d+1 mod 16).<T> }, PNn[i]`.
    @inline(__always)
    private static func decodePext(_ e: UInt32, _ a: UInt64, pair: Bool, _ sink: inout OperandSink) -> DecodedDraft {
        let element = sizeElement(e)
        let pd = UInt8(e & 0xF)
        let pnn = 8 &+ UInt8((e >> 5) & 0x7)
        let index = pair ? UInt8((e >> 8) & 0x1) : UInt8((e >> 8) & 0x3)
        let destination: Operand = pair
            ? .predicateGroup(firstIndex: pd, count: 2, element: element)
            : .scalablePredicate(ScalablePredicateRef(
                registerIndex: pd, element: element, role: .result,
            ))
        var writes = SME2Decode.predMask(pd)
        if pair { writes = writes.union(SME2Decode.predMask((pd &+ 1) & 0xF)) }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .pext,
            category: .sve,
            operandCount: sink.emit(destination, .scalablePredicate(ScalablePredicateRef(
                registerIndex: pnn, isCounter: true, elementIndex: index,
            ))),
            scalableReads: SME2Decode.predMask(pnn),
            scalableWrites: writes,
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `PTRUE PNd.<T>` — all-true counter predicate.
    @inline(__always)
    private static func decodePtrueCounter(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let pnd = 8 &+ UInt8(e & 0x7)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .ptrue,
            category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(
                registerIndex: pnd, element: sizeElement(e), role: .result, isCounter: true,
            ))),
            scalableWrites: SME2Decode.predMask(pnd),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `CNTP Xd, PNn.<T>, vlx<2|4>` — count active counter-predicate elements.
    @inline(__always)
    private static func decodeCntpCounter(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let pnn = UInt8((e >> 5) & 0xF)
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .cntp,
            semanticWrites: SME2Decode.dataMask(rd),
            category: .sve,
            operandCount: sink.emit(gprOperand(rd), .scalablePredicate(ScalablePredicateRef(
                registerIndex: pnn, element: sizeElement(e), isCounter: true,
            )), .vectorLengthMultiplier(e & 0x400 != 0 ? 4 : 2)),
            scalableReads: SME2Decode.predMask(pnn),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `FIRSTP|LASTP Xd, Pg, Pn.<T>` — index of the first/last active element.
    @inline(__always)
    private static func decodeFirstLastP(_ e: UInt32, _ a: UInt64, mnemonic: Mnemonic, _ sink: inout OperandSink) -> DecodedDraft {
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticWrites: SME2Decode.dataMask(rd),
            category: .sve,
            operandCount: sink.emit(gprOperand(rd), .scalablePredicate(ScalablePredicateRef(registerIndex: pg)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: sizeElement(e)))),
            scalableReads: SME2Decode.predMask(pg).union(SME2Decode.predMask(pn)),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// `PSEL Pd, Pn, Pm.<T>[Wv, i]` — predicate select by indexed element.
    @inline(__always)
    private static func decodePsel(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // tsz trailing-one size/index scheme: tszl bits[20:18], tszh bit22,
        // i1 bit23; tszh:tszl == 0000 is reserved.
        let tszl = UInt8((e >> 18) & 0x7)
        let tszh = UInt8((e >> 22) & 0x1)
        let i1 = UInt8((e >> 23) & 0x1)
        let element: ScalarSize
        let index: UInt8
        if tszl & 0b001 != 0 {
            element = .b
            index = (i1 << 3) | (tszh << 2) | (tszl >> 1)
        } else if tszl & 0b010 != 0 {
            element = .h
            index = (i1 << 2) | (tszh << 1) | (tszl >> 2)
        } else if tszl & 0b100 != 0 {
            element = .s
            index = (i1 << 1) | tszh
        } else if tszh != 0 {
            element = .d
            index = i1
        } else {
            return undefinedSVE(e, a) // tsz == 0000 reserved
        }
        let pd = UInt8(e & 0xF)
        let pn = UInt8((e >> 10) & 0xF)
        let pm = UInt8((e >> 5) & 0xF)
        let select = RegisterRef.w(12 &+ UInt8((e >> 16) & 0x3))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .psel,
            semanticReads: SME2Decode.selectMask(select),
            category: .sve,
            operandCount: sink.emit(.scalablePredicate(ScalablePredicateRef(registerIndex: pd, role: .result)), .scalablePredicate(ScalablePredicateRef(registerIndex: pn)), .scalablePredicate(ScalablePredicateRef(
                registerIndex: pm, element: element, elementIndex: index,
                selectRegister: select,
            ))),
            scalableReads: SME2Decode.predMask(pn).union(SME2Decode.predMask(pm)),
            scalableWrites: SME2Decode.predMask(pd),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: - shared

    /// Element size from bits[23:22].
    @inline(__always)
    private static func sizeElement(_ e: UInt32) -> ScalarSize {
        switch (e >> 22) & 0x3 {
        case 0: .b
        case 1: .h
        case 2: .s
        default: .d
        }
    }

    /// The WHILE condition mnemonic from the (unsigned, less, or-equal) bits.
    @inline(__always)
    private static func whileMnemonic(unsigned: Bool, less: Bool, orEqual: Bool) -> Mnemonic {
        if unsigned {
            less ? (orEqual ? .whilels : .whilelo) : (orEqual ? .whilehi : .whilehs)
        } else {
            less ? (orEqual ? .whilele : .whilelt) : (orEqual ? .whilegt : .whilege)
        }
    }

    /// A 64-bit GPR operand (`Xn`, `XZR` at 31).
    @inline(__always)
    private static func gprOperand(_ index: UInt8) -> Operand {
        .register(index == 31 ? .xzr() : .x(index))
    }

    /// A well-formed in-scope UNDEFINED record for a carve hole
    /// (`category = .sve`, raw encoding preserved).
    @inline(__always)
    private static func undefinedSVE(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        DecodedDraft(address: a, encoding: e, mnemonic: .undefined, category: .sve)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// SVE predicate count (G5: CNTP, INCP/DECP/SQINCP/UQINCP/
// SQDECP/UQDECP scalar+vector, plus WRFFR/SETFFR which share the region)
// and loop predicates (G6: WHILE<cc>, WHILERW/WHILEWR, CTERMEQ/CTERMNE).

extension SVEPredicateControlDecode {
    // MARK: G5 — Predicate count (+ WRFFR / SETFFR)

    @inline(__always)
    static func decodePredicateCount(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // The scope predicate pins b20==0 for this sub-region, and for b19==1 it
        // pins b13==0 and b12:11 ∈ {00,01,10} — so neither field is re-checked
        // here and the dispatch below needs no UNDEFINED arm.
        if (e >> 19) & 1 == 0 {
            return decodeCntp(e, a)
        }
        switch (e >> 11) & 0b11 {
        case 0b00: return decodeCountPredicate(e, a, scalar: false)
        case 0b01: return decodeCountPredicate(e, a, scalar: true)
        default: return decodeFfrWrite(e, a) // b12:11 == 10 — WRFFR/SETFFR.
        }
    }

    @inline(__always)
    static func decodeCntp(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // b18:16==000 and b9==0 are pinned by the scope predicate — the
        // FIRSTP/LASTP siblings (b18:16 001/010) and the CNTP-as-counter form
        // (b9==1) belong to SME2 and never arrive here.
        let sz = elementSize(e >> 22)
        let pg = UInt8((e >> 10) & 0xF)
        let pn = UInt8((e >> 5) & 0xF)
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .cntp,
            semanticWrites: gpr64Mask(rd), category: .sve,
            operands: [
                .register(gpr64(rd)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: pg, role: .governing)),
                .scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: sz)),
            ],
            scalableReads: predSet(pg).insertingPredicate(pn),
            scalableEffect: .readsStreamingMode,
        )
    }

    /// INCP/DECP/SQINCP/UQINCP/SQDECP/UQDECP — scalar (`scalar==true`) or
    /// vector. `op = b18:16`; the predicate `Pm` (b8:5) is a data SOURCE.
    @inline(__always)
    static func decodeCountPredicate(_ e: UInt32, _ a: UInt64, scalar: Bool) -> DecodedDraft {
        if (e >> 9) & 1 != 0 { return undefined(e, a) } // b9 SBZ (mask 0xFF3FFE00)
        let op = (e >> 16) & 0b111
        if op > 0b101 { return undefined(e, a) } // 110/111 unallocated
        let sz = elementSize(e >> 22)
        let pm = UInt8((e >> 5) & 0xF)
        let dn = UInt8(e & 0x1F)
        let pmOp = Operand.scalablePredicate(ScalablePredicateRef(registerIndex: pm, element: sz))
        let pmReads = predSet(pm)
        if !scalar {
            // Vector: sz==00 (B) is UNDEFINED; b10 SBZ (the 32/64 bit is
            // scalar-only). Zdn read+written, full write.
            if (e >> 22) & 0b11 == 0 || (e >> 10) & 1 != 0 { return undefined(e, a) }
            let mnemonic = countPredicateVectorMnemonic(op)
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: vecMask(dn), semanticWrites: vecMask(dn), category: .sve,
                operands: [
                    .scalableVector(ScalableVectorRef(registerIndex: dn, element: sz)),
                    pmOp,
                ],
                scalableReads: pmReads, scalableEffect: .readsStreamingMode,
            )
        }
        // Scalar. INCP/DECP (100/101): b10 must be 0, X dest. Saturating
        // (000-011): b10 selects 32/64-bit.
        if op >= 0b100 {
            if (e >> 10) & 1 != 0 { return undefined(e, a) }
            let mnemonic: Mnemonic = op == 0b100 ? .incp : .decp
            return DecodedDraft(
                address: a, encoding: e, mnemonic: mnemonic,
                semanticReads: gpr64Mask(dn), semanticWrites: gpr64Mask(dn), category: .sve,
                operands: [.register(gpr64(dn)), pmOp],
                scalableReads: pmReads, scalableEffect: .readsStreamingMode,
            )
        }
        // Saturating scalar. Signed (op even: SQINCP/SQDECP) 32-bit form
        // renders X dest + trailing W source-view; unsigned (op odd:
        // UQINCP/UQDECP) 32-bit form renders a W dest.
        let is64 = (e >> 10) & 1 == 1
        let mnemonic = countPredicateSatMnemonic(op)
        let mask = gpr64Mask(dn) // same physical reg for every view
        var ops: [Operand] = [.register(gpr64(dn)), pmOp]
        ops.reserveCapacity(3)
        if !is64 {
            let signed = op & 1 == 0
            if signed {
                ops.append(.register(gpr32(dn))) // trailing 32-bit source-view
            } else {
                ops[0] = .register(gpr32(dn)) // W dest
            }
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: mask, semanticWrites: mask, category: .sve,
            operands: ops, scalableReads: pmReads, scalableEffect: .readsStreamingMode,
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
        default: .uqdecp // 0b011
        }
    }

    @inline(__always)
    static func decodeFfrWrite(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // b12:11==10. b18: 0=WRFFR, 1=SETFFR. b23:22, b17:16, b10:9, b4:0 fixed.
        if (e >> 22) & 0b11 != 0 || (e >> 16) & 0b11 != 0 || (e >> 9) & 0b11 != 0 || (e & 0x1F) != 0 {
            return undefined(e, a)
        }
        if (e >> 18) & 1 == 1 {
            // SETFFR — b8:5 must also be 0.
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
            operands: [.scalablePredicate(ScalablePredicateRef(registerIndex: pn, element: .b))],
            scalableReads: predSet(pn),
            scalableWrites: ScalableRegisterSet.empty.insertingFFR(),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G6 — Loop predicates (WHILE / WHILERW / WHILEWR / CTERM)

    @inline(__always)
    static func decodeWhileTerm(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        if (e >> 13) & 1 == 0 {
            return decodeWhile(e, a)
        }
        let b12_10 = (e >> 10) & 0b111
        if b12_10 == 0b000 {
            return decodeCterm(e, a)
        }
        // b12:10 == 100 — WHILERW/WHILEWR. With b13==1 the scope predicate
        // admits only 000 above and 100 here, so no UNDEFINED tail is
        // reachable.
        return decodeWhileRwWr(e, a)
    }

    @inline(__always)
    static func decodeWhile(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // sz=b23:22, sf=b12 (0=W,1=X), U=b11, lt=b10, eq=b4. cc from (U,lt,eq).
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
            operands: [
                .scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: sz, role: .result)),
                rnOp, rmOp,
            ],
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
        default: .whilels // 0b111
        }
    }

    @inline(__always)
    static func decodeWhileRwWr(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // Operands always X. b4: 0=WR, 1=RW.
        let sz = elementSize(e >> 22)
        let rm = UInt8((e >> 16) & 0x1F)
        let rn = UInt8((e >> 5) & 0x1F)
        let pd = UInt8(e & 0xF)
        let mnemonic: Mnemonic = (e >> 4) & 1 == 1 ? .whilerw : .whilewr
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: gpr64Mask(rn).union(gpr64Mask(rm)),
            flagEffect: .nzcv, category: .sve,
            operands: [
                .scalablePredicate(ScalablePredicateRef(registerIndex: pd, element: sz, role: .result)),
                .register(gpr64(rn)), .register(gpr64(rm)),
            ],
            scalableWrites: predSet(pd), scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeCterm(_ e: UInt32, _ a: UInt64) -> DecodedDraft {
        // b23 must be 1, b3:0 must be 0. sz=b22 (0=W,1=X). b4: 0=EQ,1=NE.
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
        // CTERM writes N,V only and reads C — its own flag set,
        // NOT .nzcv, and NOT readsStreamingMode (pure GPR compare).
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic, semanticReads: reads,
            flagEffect: [.writesN, .writesV, .readsC], category: .sve,
            operands: [rnOp, rmOp],
        )
    }

    // MARK: GPR helpers (XZR-dropping masks; SP handled by the ADD?L forms)

    /// A GPR64 ref where index 31 is XZR (so `insertingNonZero`/`gpr64Mask`
    /// drop it — a ZR access is not a dependency).
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

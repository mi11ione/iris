// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the 0x04-region carve-out: element count + stack-frame
// adjust (G7: CNTB/H/W/D, INC/DEC/SQINC/UQINC/SQDEC/UQDEC by element count,
// RDVL/RDSVL/ADDVL/ADDSVL/ADDPL/ADDSPL), index generation (G8: INDEX ×4),
// and the constructive prefix (G9: MOVPRFX unpredicated + predicated).

extension SVEPredicateControlDecode {
    /// 0x04 region sub-dispatch (G7–G9).
    @inline(__always)
    static func decodeIntegerRegion(encoding e: UInt32, address a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 21) & 1 == 0 {
            return decodeMovprfxPredicated(e, a, &sink)
        }
        switch (e >> 12) & 0b1111 {
        case 0b0100:
            return decodeIndex(e, a, &sink)
        case 0b0101:
            return (e >> 23) & 1 == 1 ? decodeRdvl(e, a, &sink) : decodeAddvlAddpl(e, a, &sink)
        case 0b1011:
            return decodeMovprfxUnpredicated(e, a, &sink)
        case 0b1100:
            return decodeElementCountVector(e, a, &sink)
        case 0b1110:
            return decodeCntIncDecScalar(e, a, &sink)
        // 1111 — SQINC/UQINC/SQDEC/UQDEC scalar. The carve-out
        // (`isIntegerRegionInScope`) admits only the six values of bits[15:12]
        // switched on here, so the dispatch needs no unreachable UNDEFINED arm.
        default:
            return decodeSaturatingScalar(e, a, &sink)
        }
    }

    // MARK: G7 — Element count scalar (CNT / INC / DEC)

    @inline(__always)
    static func decodeCntIncDecScalar(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        if (e >> 11) & 1 != 0 { return undefined(e, a) }
        let sz = (e >> 22) & 0b11
        let isInc = (e >> 20) & 0b11 == 0b11 // b21:20: 10=CNT, 11=INC/DEC
        let mnemonic: Mnemonic
        var reads = RegisterSet.empty
        if isInc {
            let dec = (e >> 10) & 1 == 1
            mnemonic = dec ? decScalarMnemonic(sz) : incScalarMnemonic(sz)
            reads = gpr64Mask(UInt8(e & 0x1F)) // Rdn read+written
        } else {
            if (e >> 10) & 1 != 0 { return undefined(e, a) } // CNT requires b10=0
            mnemonic = cntMnemonic(sz)
        }
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: reads, semanticWrites: gpr64Mask(rd), category: .sve,
            operandCount: sink.emit(.register(gpr64(rd)), patternOperand(e)),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G7 — Saturating element count scalar (SQINC/UQINC/SQDEC/UQDEC)

    @inline(__always)
    static func decodeSaturatingScalar(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let op = (e >> 10) & 0b11 // 00 SQINC, 01 UQINC, 10 SQDEC, 11 UQDEC
        let is64 = (e >> 20) & 1 == 1
        let dn = UInt8(e & 0x1F)
        let mnemonic = satScalarMnemonic(op, sz)
        let mask = gpr64Mask(dn)
        // The destination register is decided BEFORE anything is emitted: the
        // 32-bit unsigned forms replace it rather than append, which a sink
        // cannot do after the fact.
        let signed = op & 1 == 0 // SQINC/SQDEC render X dest + trailing W source-view
        let dest: Operand = (!is64 && !signed) ? .register(gpr32(dn)) : .register(gpr64(dn))
        let operandCount: UInt8 = (!is64 && signed)
            ? sink.emit(dest, .register(gpr32(dn)), patternOperand(e))
            : sink.emit(dest, patternOperand(e))
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: mask, semanticWrites: mask, category: .sve,
            operandCount: operandCount, scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G7 — Element count vector (INC/DEC/SQINC/UQINC/SQDEC/UQDEC)

    @inline(__always)
    static func decodeElementCountVector(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        if sz == 0 { return undefined(e, a) } // no .B vector form
        let saturating = (e >> 20) & 1 == 0
        let op = (e >> 10) & 0b11
        if !saturating, op >= 0b10 { return undefined(e, a) } // plain: only INC(00)/DEC(01)
        let mnemonic = saturating ? satVectorMnemonic(op, sz) : plainVectorMnemonic(op, sz)
        let element = elementSize(sz)
        let dn = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: vecMask(dn), semanticWrites: vecMask(dn), category: .sve,
            operandCount: sink.emit(.scalableVector(ScalableVectorRef(registerIndex: dn, element: element)), patternOperand(e)),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G7 — RDVL / RDSVL / ADDVL / ADDSVL / ADDPL / ADDSPL

    @inline(__always)
    static func decodeRdvl(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b22 must be 0, b20:16 must be 11111. b11: 0=RDVL, 1=RDSVL.
        if (e >> 22) & 1 != 0 || (e >> 16) & 0x1F != 0x1F { return undefined(e, a) }
        let streaming = (e >> 11) & 1 == 1
        let rd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: streaming ? .rdsvl : .rdvl,
            semanticWrites: gpr64Mask(rd), category: .sve,
            operandCount: sink.emit(.register(gpr64(rd)), .immediate(value: signExtend(e >> 5, bits: 6), width: 6)),
            // RDVL result is VL (SM-dependent → readsStreamingMode); RDSVL is
            // SVL (SM-independent → CLEAR).
            scalableEffect: streaming ? .none : .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeAddvlAddpl(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b22: 0=VL,1=PL. b11: 0=non-streaming,1=streaming. Rd/Rn are SP-class.
        let pl = (e >> 22) & 1 == 1
        let streaming = (e >> 11) & 1 == 1
        let mnemonic: Mnemonic = pl
            ? (streaming ? .addspl : .addpl)
            : (streaming ? .addsvl : .addvl)
        let rd = UInt8(e & 0x1F)
        let rn = UInt8((e >> 16) & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: mnemonic,
            semanticReads: gprSPMask(rn), semanticWrites: gprSPMask(rd), category: .sve,
            operandCount: sink.emit(.register(gprSP(rd)), .register(gprSP(rn)), .immediate(value: signExtend(e >> 5, bits: 6), width: 6)),
            scalableEffect: streaming ? .none : .readsStreamingMode,
        )
    }

    // MARK: G8 — INDEX

    @inline(__always)
    static func decodeIndex(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        let sz = (e >> 22) & 0b11
        let element = elementSize(sz)
        let startIsReg = (e >> 10) & 1 == 1 // b10: first operand (b9:5) is a register
        let stepIsReg = (e >> 11) & 1 == 1 // b11: second operand (b20:16) is a register
        let start = UInt32((e >> 5) & 0x1F)
        let step = UInt32((e >> 16) & 0x1F)
        let zd = UInt8(e & 0x1F)
        var reads = RegisterSet.empty
        let startOp: Operand
        if startIsReg {
            startOp = .register(indexReg(UInt8(start), sz: sz))
            reads = reads.union(indexRegMask(UInt8(start), sz: sz))
        } else {
            startOp = .immediate(value: signExtend(start, bits: 5), width: 5)
        }
        let stepOp: Operand
        if stepIsReg {
            stepOp = .register(indexReg(UInt8(step), sz: sz))
            reads = reads.union(indexRegMask(UInt8(step), sz: sz))
        } else {
            stepOp = .immediate(value: signExtend(step, bits: 5), width: 5)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .index,
            semanticReads: reads, semanticWrites: vecMask(zd), category: .sve,
            operandCount: sink.emit(.scalableVector(ScalableVectorRef(registerIndex: zd, element: element)), startOp, stepOp),
            scalableEffect: .readsStreamingMode,
        )
    }

    // MARK: G9 — MOVPRFX

    @inline(__always)
    static func decodeMovprfxUnpredicated(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b15:11==10111, b10==1, b23:22==00, b20:16==00000.
        if (e >> 10) & 0b111111 != 0b101111 || (e >> 22) & 0b11 != 0 || (e >> 16) & 0x1F != 0 {
            return undefined(e, a)
        }
        let zn = UInt8((e >> 5) & 0x1F)
        let zd = UInt8(e & 0x1F)
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .movprfx,
            semanticReads: vecMask(zn), semanticWrites: vecMask(zd), category: .sve,
            operandCount: sink.emit(.scalableVector(ScalableVectorRef(registerIndex: zd)), .scalableVector(ScalableVectorRef(registerIndex: zn))),
            scalableEffect: .readsStreamingMode,
        )
    }

    @inline(__always)
    static func decodeMovprfxPredicated(_ e: UInt32, _ a: UInt64, _ sink: inout OperandSink) -> DecodedDraft {
        // b21:19==010, b18:17==00, b15:13==001 — pinned by the carve-out
        // (`isIntegerRegionInScope`'s bit21=0 arm tests exactly these three
        // fields), so a bit21=0 word arriving here is a MOVPRFX and needs no
        // re-check. M=b16, sz=b23:22, Pg=b12:10 (3-bit).
        let merging = (e >> 16) & 1 == 1
        let element = elementSize(e >> 22)
        let pg = UInt8((e >> 10) & 0b111) // 3-bit → P0-P7
        let zn = UInt8((e >> 5) & 0x1F)
        let zd = UInt8(e & 0x1F)
        var reads = vecMask(zn)
        var effect: ScalableEffect = .readsStreamingMode
        if merging {
            reads = reads.union(vecMask(zd)) // /M reads Zd (RMW)
            effect.insert(.partialWrite)
        }
        return DecodedDraft(
            address: a, encoding: e, mnemonic: .movprfx,
            semanticReads: reads, semanticWrites: vecMask(zd), category: .sve,
            operandCount: sink.emit(.scalableVector(ScalableVectorRef(registerIndex: zd, element: element)), .scalablePredicate(ScalablePredicateRef(registerIndex: pg, qualifier: merging ? .merging : .zeroing, role: .governing)), .scalableVector(ScalableVectorRef(registerIndex: zn, element: element))),
            scalableReads: predSet(pg), scalableEffect: effect,
        )
    }

    // MARK: pattern / immediate / register helpers

    /// The `<pat>{, MUL #k}` operand carrying raw pattern (b9:5) and
    /// multiplier (imm4+1, from b19:16); the canonicalizer applies the
    /// 3-tier elision.
    @inline(__always)
    static func patternOperand(_ e: UInt32) -> Operand {
        let pat = UInt8((e >> 5) & 0b11111)
        let mul = UInt8((e >> 16) & 0b1111) &+ 1
        return .svePredicatePattern(SVEPredicatePattern(raw: pat, multiplier: mul))
    }

    /// Sign-extend the low `bits` of `value` to a signed `Int64`.
    @inline(__always)
    static func signExtend(_ value: UInt32, bits: UInt32) -> Int64 {
        let v = Int64(value & ((UInt32(1) << bits) - 1))
        let signBit = Int64(1) << (bits - 1)
        return (v ^ signBit) &- signBit
    }

    /// INDEX register operand — W for B/H/S, X for D; ZR-class (reg31 dropped).
    @inline(__always)
    static func indexReg(_ n: UInt8, sz: UInt32) -> RegisterRef {
        sz == 0b11 ? gpr64(n) : gpr32(n)
    }

    @inline(__always)
    static func indexRegMask(_ n: UInt8, sz: UInt32) -> RegisterSet {
        sz == 0b11 ? gpr64Mask(n) : gpr32Mask(n)
    }

    /// A GPR64 ref where index 31 is SP (role .stackPointer), so it stays in
    /// the mask — ADDVL/ADDPL/ADDSVL/ADDSPL's `<Xn|SP>`/`<Xd|SP>` operands.
    @inline(__always)
    static func gprSP(_ n: UInt8) -> RegisterRef {
        n & 0x1F == 31 ? .sp() : .x(n & 0x1F)
    }

    @inline(__always)
    static func gprSPMask(_ n: UInt8) -> RegisterSet {
        RegisterSet.empty.inserting(gprSP(n))
    }

    // MARK: element-count mnemonic tables

    @inline(__always)
    static func cntMnemonic(_ sz: UInt32) -> Mnemonic {
        switch sz { case 0: .cntb; case 1: .cnth; case 2: .cntw; default: .cntd }
    }

    @inline(__always)
    static func incScalarMnemonic(_ sz: UInt32) -> Mnemonic {
        switch sz { case 0: .incb; case 1: .inch; case 2: .incw; default: .incd }
    }

    @inline(__always)
    static func decScalarMnemonic(_ sz: UInt32) -> Mnemonic {
        switch sz { case 0: .decb; case 1: .dech; case 2: .decw; default: .decd }
    }

    @inline(__always)
    static func satScalarMnemonic(_ op: UInt32, _ sz: UInt32) -> Mnemonic {
        switch op {
        case 0b00: switch sz { case 0: return .sqincb; case 1: return .sqinch; case 2: return .sqincw; default: return .sqincd }
        case 0b01: switch sz { case 0: return .uqincb; case 1: return .uqinch; case 2: return .uqincw; default: return .uqincd }
        case 0b10: switch sz { case 0: return .sqdecb; case 1: return .sqdech; case 2: return .sqdecw; default: return .sqdecd }
        default: switch sz { case 0: return .uqdecb; case 1: return .uqdech; case 2: return .uqdecw; default: return .uqdecd }
        }
    }

    /// Vector plain INC/DEC — no `.B` form, so `sz` is 1..3.
    @inline(__always)
    static func plainVectorMnemonic(_ op: UInt32, _ sz: UInt32) -> Mnemonic {
        if op == 0b00 {
            switch sz { case 1: return .inch; case 2: return .incw; default: return .incd }
        }
        switch sz { case 1: return .dech; case 2: return .decw; default: return .decd }
    }

    /// Vector saturating SQINC/UQINC/SQDEC/UQDEC — no `.B` form.
    @inline(__always)
    static func satVectorMnemonic(_ op: UInt32, _ sz: UInt32) -> Mnemonic {
        switch op {
        case 0b00: switch sz { case 1: return .sqinch; case 2: return .sqincw; default: return .sqincd }
        case 0b01: switch sz { case 1: return .uqinch; case 2: return .uqincw; default: return .uqincd }
        case 0b10: switch sz { case 1: return .sqdech; case 2: return .sqdecw; default: return .sqdecd }
        default: switch sz { case 1: return .uqdech; case 2: return .uqdecw; default: return .uqdecd }
        }
    }
}

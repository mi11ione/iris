// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical llvm-mc-compatible disassembly text for an SVE predicate &
/// control record.
enum SVEPredicateControlCanonicalizer {
    /// The byte path.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        let ops = instruction.operands
        let m = instruction.mnemonic
        switch m {
        case .ptrue, .ptrues:
            putPtrue(m, ops, into: &out)
        case .pfalse:
            putHead(m, into: &out)
            putPred(ops, 0, into: &out)
        case .ptest:
            putHead(m, into: &out)
            putPred(ops, 0, into: &out)
            out.put(", ")
            putPred(ops, 1, into: &out)
        case .and, .ands, .bic, .bics, .eor, .eors, .orr, .orrs, .orn, .orns,
             .nand, .nands, .nor, .nors, .sel:
            putFour(m, ops, into: &out)
        case .mov, .movs, .not, .nots:
            if ops.count == 2 {
                putHead(m, into: &out)
                putPred(ops, 0, into: &out)
                out.put(", ")
                putPred(ops, 1, into: &out)
            } else {
                putThree(m, ops, into: &out)
            }
        case .brka, .brkas, .brkb, .brkbs:
            putThree(m, ops, into: &out)
        case .brkn, .brkns, .brkpa, .brkpas, .brkpb, .brkpbs:
            putFour(m, ops, into: &out)
        case .pfirst, .pnext:
            putThree(m, ops, into: &out)
        case .rdffr, .rdffrs:
            putHead(m, into: &out)
            putPred(ops, 0, into: &out)
            if ops.count != 1 {
                out.put(", ")
                putPred(ops, 1, into: &out)
            }
        case .wrffr:
            putHead(m, into: &out)
            putPred(ops, 0, into: &out)
        case .setffr:
            putGroupName(m, into: &out)
        case .cntp:
            putHead(m, into: &out)
            putReg(ops, 0, into: &out)
            out.put(", ")
            putPred(ops, 1, into: &out)
            out.put(", ")
            putPred(ops, 2, into: &out)
        case .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp:
            putCountPredicate(m, ops, into: &out)
        case .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi,
             .whilelo, .whilels, .whilerw, .whilewr:
            putHead(m, into: &out)
            putPred(ops, 0, into: &out)
            out.put(", ")
            putReg(ops, 1, into: &out)
            out.put(", ")
            putReg(ops, 2, into: &out)
        case .ctermeq, .ctermne:
            putHead(m, into: &out)
            putReg(ops, 0, into: &out)
            out.put(", ")
            putReg(ops, 1, into: &out)
        case .rdvl, .rdsvl:
            putHead(m, into: &out)
            putReg(ops, 0, into: &out)
            out.put(", ")
            putImm(ops, 1, into: &out)
        case .addvl, .addsvl, .addpl, .addspl:
            putHead(m, into: &out)
            putReg(ops, 0, into: &out)
            out.put(", ")
            putReg(ops, 1, into: &out)
            out.put(", ")
            putImm(ops, 2, into: &out)
        case .cntb, .cnth, .cntw, .cntd:
            putElementCount(m, ops, destCount: 1, into: &out)
        case .incb, .inch, .incw, .incd, .decb, .dech, .decw, .decd,
             .sqincb, .sqinch, .sqincw, .sqincd, .uqincb, .uqinch, .uqincw, .uqincd,
             .sqdecb, .sqdech, .sqdecw, .sqdecd, .uqdecb, .uqdech, .uqdecw, .uqdecd:
            putElementCount(m, ops, destCount: elementCountDestCount(ops), into: &out)
        case .index:
            putHead(m, into: &out)
            putScalableVector(ops, 0, into: &out)
            out.put(", ")
            putIndexOperand(ops, 1, into: &out)
            out.put(", ")
            putIndexOperand(ops, 2, into: &out)
        case .movprfx:
            putHead(m, into: &out)
            putScalableVector(ops, 0, into: &out)
            out.put(", ")
            if ops.count == 2 {
                putScalableVector(ops, 1, into: &out)
            } else {
                putPred(ops, 1, into: &out)
                out.put(", ")
                putScalableVector(ops, 2, into: &out)
            }
        default:
            putGroupName(m, into: &out)
        }
    }

    @inline(__always)
    private static func putHead(_ m: Mnemonic, into out: inout TextBytes) {
        putGroupName(m, into: &out)
        out.put(UInt8(ascii: " "))
    }

    /// This group's own spelling table.
    @inline(__always)
    private static func putGroupName(_ m: Mnemonic, into out: inout TextBytes) {
        if let spelling = name(m) {
            out.put(spelling)
        } else {
            out.put(UInt8(ascii: "?"))
            out.putDecimal(UInt64(m.rawValue))
        }
    }

    private static func putPtrue(
        _ m: Mnemonic, _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        putHead(m, into: &out)
        putPred(ops, 0, into: &out)
        guard case let .svePredicatePattern(pat) = operand(ops, ops.count - 1) else { return }
        if SVEPatternName.isAll(pat.raw) { return }
        out.put(", ")
        out.putString(SVEPatternName.text(pat.raw))
    }

    private static func putFour(
        _ m: Mnemonic, _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        putHead(m, into: &out)
        for i in 0 ..< 4 {
            if i > 0 { out.put(", ") }
            putPred(ops, i, into: &out)
        }
    }

    private static func putThree(
        _ m: Mnemonic, _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        putHead(m, into: &out)
        for i in 0 ..< 3 {
            if i > 0 { out.put(", ") }
            putPred(ops, i, into: &out)
        }
    }

    private static func putCountPredicate(
        _ m: Mnemonic, _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        putHead(m, into: &out)
        if case .scalableVector = operand(ops, 0) {
            putScalableVector(ops, 0, into: &out)
            out.put(", ")
            putPred(ops, 1, into: &out)
            return
        }
        putReg(ops, 0, into: &out)
        out.put(", ")
        putPred(ops, 1, into: &out)
        if ops.count >= 3 {
            out.put(", ")
            putReg(ops, 2, into: &out)
        }
    }

    private static func putElementCount(
        _ m: Mnemonic, _ ops: Instruction.Operands, destCount: Int, into out: inout TextBytes,
    ) {
        putHead(m, into: &out)
        if destCount == 2 {
            putReg(ops, 0, into: &out)
            out.put(", ")
            putReg(ops, 1, into: &out)
        } else if case .scalableVector = operand(ops, 0) {
            putScalableVector(ops, 0, into: &out)
        } else {
            putReg(ops, 0, into: &out)
        }
        guard case let .svePredicatePattern(pat) = operand(ops, destCount) else { return }
        let mulPresent = pat.multiplier != 1
        if SVEPatternName.isAll(pat.raw), !mulPresent { return }
        out.put(", ")
        out.putString(SVEPatternName.text(pat.raw))
        if mulPresent {
            out.put(", mul #")
            out.putDecimal(UInt64(pat.multiplier))
        }
    }

    /// The number of leading register operands before the pattern for an
    /// element-count form.
    private static func elementCountDestCount(_ ops: Instruction.Operands) -> Int {
        if ops.count >= 2, case .register = ops[0], case .register = ops[1] {
            return 2
        }
        return 1
    }

    /// A predicate operand.
    private static func putPred(
        _ ops: Instruction.Operands, _ i: Int, into out: inout TextBytes,
    ) {
        guard case let .scalablePredicate(p) = operand(ops, i) else {
            out.put("?p")
            return
        }
        out.put(UInt8(ascii: "p"))
        out.putDecimal(UInt64(p.registerIndex))
        if let el = p.element {
            out.put(UInt8(ascii: "."))
            putElementSuffix(el, into: &out)
        }
        switch p.qualifier {
        case .zeroing: out.put("/z")
        case .merging: out.put("/m")
        case .none: break
        }
    }

    private static func putScalableVector(
        _ ops: Instruction.Operands, _ i: Int, into out: inout TextBytes,
    ) {
        guard case let .scalableVector(v) = operand(ops, i) else {
            out.put("?z")
            return
        }
        out.put(UInt8(ascii: "z"))
        out.putDecimal(UInt64(v.registerIndex))
        if let el = v.element {
            out.put(UInt8(ascii: "."))
            putElementSuffix(el, into: &out)
        }
    }

    private static func putReg(
        _ ops: Instruction.Operands, _ i: Int, into out: inout TextBytes,
    ) {
        guard case let .register(r) = operand(ops, i) else {
            out.put("?r")
            return
        }
        putRegister(r, into: &out)
    }

    private static func putImm(
        _ ops: Instruction.Operands, _ i: Int, into out: inout TextBytes,
    ) {
        switch operand(ops, i) {
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        default:
            out.put("?#")
        }
    }

    /// An INDEX start/step operand.
    private static func putIndexOperand(
        _ ops: Instruction.Operands, _ i: Int, into out: inout TextBytes,
    ) {
        switch operand(ops, i) {
        case let .register(r): putRegister(r, into: &out)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        default: out.put("?idx")
        }
    }

    @inline(__always)
    private static func operand(_ ops: Instruction.Operands, _ i: Int) -> Operand {
        (i >= 0 && i < ops.count) ? ops[i] : .immediate(value: 0, width: 0)
    }

    @inline(__always)
    private static func putElementSuffix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        case .d: out.put("d")
        case .q: out.put("q")
        }
    }

    private static func putRegister(_ r: RegisterRef, into out: inout TextBytes) {
        switch (r.canonicalIndex, r.role, r.width) {
        case (31, .stackPointer, .x64): out.put("sp")
        case (31, .stackPointer, .w32): out.put("wsp")
        case (31, .zeroRegister, .x64): out.put("xzr")
        case (31, .zeroRegister, .w32): out.put("wzr")
        case (31, .general, _): out.put(r.width == .x64 ? "xzr" : "wzr")
        default:
            let n = r.canonicalIndex
            if n < 31 {
                out.put(r.width == .x64 ? "x" : "w")
                out.putDecimal(UInt64(n))
            } else {
                out.put(UInt8(ascii: "?"))
                out.putDecimal(UInt64(n))
            }
        }
    }

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
        switch m {
        case .ptrue: "ptrue"
        case .ptrues: "ptrues"
        case .pfalse: "pfalse"
        case .ptest: "ptest"
        case .and: "and"
        case .ands: "ands"
        case .bic: "bic"
        case .bics: "bics"
        case .eor: "eor"
        case .eors: "eors"
        case .orr: "orr"
        case .orrs: "orrs"
        case .orn: "orn"
        case .orns: "orns"
        case .nand: "nand"
        case .nands: "nands"
        case .nor: "nor"
        case .nors: "nors"
        case .sel: "sel"
        case .mov: "mov"
        case .movs: "movs"
        case .not: "not"
        case .nots: "nots"
        case .brka: "brka"
        case .brkas: "brkas"
        case .brkb: "brkb"
        case .brkbs: "brkbs"
        case .brkn: "brkn"
        case .brkns: "brkns"
        case .brkpa: "brkpa"
        case .brkpas: "brkpas"
        case .brkpb: "brkpb"
        case .brkpbs: "brkpbs"
        case .pfirst: "pfirst"
        case .pnext: "pnext"
        case .rdffr: "rdffr"
        case .rdffrs: "rdffrs"
        case .wrffr: "wrffr"
        case .setffr: "setffr"
        case .cntp: "cntp"
        case .incp: "incp"
        case .decp: "decp"
        case .sqincp: "sqincp"
        case .uqincp: "uqincp"
        case .sqdecp: "sqdecp"
        case .uqdecp: "uqdecp"
        case .whilege: "whilege"
        case .whilegt: "whilegt"
        case .whilelt: "whilelt"
        case .whilele: "whilele"
        case .whilehs: "whilehs"
        case .whilehi: "whilehi"
        case .whilelo: "whilelo"
        case .whilels: "whilels"
        case .whilerw: "whilerw"
        case .whilewr: "whilewr"
        case .ctermeq: "ctermeq"
        case .ctermne: "ctermne"
        case .rdvl: "rdvl"
        case .rdsvl: "rdsvl"
        case .addvl: "addvl"
        case .addsvl: "addsvl"
        case .addpl: "addpl"
        case .addspl: "addspl"
        case .cntb: "cntb"
        case .cnth: "cnth"
        case .cntw: "cntw"
        case .cntd: "cntd"
        case .incb: "incb"
        case .inch: "inch"
        case .incw: "incw"
        case .incd: "incd"
        case .decb: "decb"
        case .dech: "dech"
        case .decw: "decw"
        case .decd: "decd"
        case .sqincb: "sqincb"
        case .sqinch: "sqinch"
        case .sqincw: "sqincw"
        case .sqincd: "sqincd"
        case .uqincb: "uqincb"
        case .uqinch: "uqinch"
        case .uqincw: "uqincw"
        case .uqincd: "uqincd"
        case .sqdecb: "sqdecb"
        case .sqdech: "sqdech"
        case .sqdecw: "sqdecw"
        case .sqdecd: "sqdecd"
        case .uqdecb: "uqdecb"
        case .uqdech: "uqdech"
        case .uqdecw: "uqdecw"
        case .uqdecd: "uqdecd"
        case .index: "index"
        case .movprfx: "movprfx"
        default: nil
        }
    }
}

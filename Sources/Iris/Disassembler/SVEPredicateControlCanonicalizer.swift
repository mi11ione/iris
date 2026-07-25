// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer for SVE-predicate — SVE predicate & control. Renders a
// decoded record to llvm-mc-compatible disassembly text (the validator's
// parity oracle over the full op0=2 in-scope space). Per-mnemonic format
// dispatch covers every rendering rule: the governing-predicate-
// bare / other-predicate-suffixed rule, /z-/m qualifiers, the 32-value
// pattern table, the 3-tier pattern/mul elision ladder, signed-vs-unsigned
// scalar widths, SP-vs-XZR register text, and the INDEX/MOVPRFX shapes.

/// Canonical llvm-mc-compatible disassembly text for an SVE predicate &
/// control record. A scalable-tier hole never reaches here: the text router
/// renders it as `.long` before dispatching.
enum SVEPredicateControlCanonicalizer {
    /// Format `draft` to canonical disassembly text.
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        let ops = Array(instruction.operands)
        switch instruction.mnemonic {
        // G1 — initialise / test.
        case .ptrue, .ptrues:
            return formatPtrue(instruction.mnemonic, ops)
        case .pfalse:
            return "\(name(instruction.mnemonic)) \(pred(ops, 0))"
        case .ptest:
            return "\(name(instruction.mnemonic)) \(pred(ops, 0)), \(pred(ops, 1))"
        // G2 — predicate logical (4-op /z, or SEL bare Pg).
        case .and, .ands, .bic, .bics, .eor, .eors, .orr, .orrs, .orn, .orns,
             .nand, .nands, .nor, .nors, .sel:
            return formatFour(instruction.mnemonic, ops)
        // G2 aliases.
        case .mov, .movs, .not, .nots:
            return formatMovNot(instruction.mnemonic, ops)
        // G3 — break (3-op), break-pair (4-op), pfirst/pnext (3-op).
        case .brka, .brkas, .brkb, .brkbs:
            return formatThree(instruction.mnemonic, ops)
        case .brkn, .brkns, .brkpa, .brkpas, .brkpb, .brkpbs:
            return formatFour(instruction.mnemonic, ops)
        case .pfirst, .pnext:
            return formatThree(instruction.mnemonic, ops)
        // G4 — first-fault.
        case .rdffr, .rdffrs:
            return formatRdffr(instruction.mnemonic, ops)
        case .wrffr:
            return "\(name(instruction.mnemonic)) \(pred(ops, 0))"
        case .setffr:
            return name(instruction.mnemonic)
        // G5 — predicate count.
        case .cntp:
            return "\(name(instruction.mnemonic)) \(reg(ops, 0)), \(pred(ops, 1)), \(pred(ops, 2))"
        case .incp, .decp, .sqincp, .uqincp, .sqdecp, .uqdecp:
            return formatCountPredicate(instruction.mnemonic, ops)
        // G6 — loop predicates.
        case .whilege, .whilegt, .whilelt, .whilele, .whilehs, .whilehi,
             .whilelo, .whilels, .whilerw, .whilewr:
            return "\(name(instruction.mnemonic)) \(pred(ops, 0)), \(reg(ops, 1)), \(reg(ops, 2))"
        case .ctermeq, .ctermne:
            return "\(name(instruction.mnemonic)) \(reg(ops, 0)), \(reg(ops, 1))"
        // G7 — element count + adjust.
        case .rdvl, .rdsvl:
            return "\(name(instruction.mnemonic)) \(reg(ops, 0)), \(imm(ops, 1))"
        case .addvl, .addsvl, .addpl, .addspl:
            return "\(name(instruction.mnemonic)) \(reg(ops, 0)), \(reg(ops, 1)), \(imm(ops, 2))"
        case .cntb, .cnth, .cntw, .cntd:
            return formatElementCount(instruction.mnemonic, ops, destCount: 1)
        case .incb, .inch, .incw, .incd, .decb, .dech, .decw, .decd,
             .sqincb, .sqinch, .sqincw, .sqincd, .uqincb, .uqinch, .uqincw, .uqincd,
             .sqdecb, .sqdech, .sqdecw, .sqdecd, .uqdecb, .uqdech, .uqdecw, .uqdecd:
            return formatElementCount(instruction.mnemonic, ops, destCount: elementCountDestCount(ops))
        // G8 — index.
        case .index:
            return "\(name(instruction.mnemonic)) \(scalableVectorText(ops, 0)), \(indexOperand(ops, 1)), \(indexOperand(ops, 2))"
        // G9 — movprfx.
        case .movprfx:
            return formatMovprfx(instruction.mnemonic, ops)
        default:
            return name(instruction.mnemonic) // sentinel for a mnemonic outside the group
        }
    }

    // MARK: per-shape formatters

    @_effects(readonly)
    private static func formatPtrue(_ m: Mnemonic, _ ops: [Operand]) -> String {
        // PTRUE always elides the `all` (31) pattern (no mul field).
        guard case let .svePredicatePattern(pat) = operand(ops, ops.count - 1) else {
            return "\(name(m)) \(pred(ops, 0))"
        }
        if SVEPatternName.isAll(pat.raw) {
            return "\(name(m)) \(pred(ops, 0))"
        }
        return "\(name(m)) \(pred(ops, 0)), \(SVEPatternName.text(pat.raw))"
    }

    @_effects(readonly)
    private static func formatFour(_ m: Mnemonic, _ ops: [Operand]) -> String {
        "\(name(m)) \(pred(ops, 0)), \(pred(ops, 1)), \(pred(ops, 2)), \(pred(ops, 3))"
    }

    @_effects(readonly)
    private static func formatThree(_ m: Mnemonic, _ ops: [Operand]) -> String {
        "\(name(m)) \(pred(ops, 0)), \(pred(ops, 1)), \(pred(ops, 2))"
    }

    @_effects(readonly)
    private static func formatMovNot(_ m: Mnemonic, _ ops: [Operand]) -> String {
        // MOV/MOVS have a 2-operand form (from ORR/ORRS) and a 3-operand form
        // (from AND/ANDS or SEL); NOT/NOTS are always 3-operand.
        if ops.count == 2 {
            return "\(name(m)) \(pred(ops, 0)), \(pred(ops, 1))"
        }
        return formatThree(m, ops)
    }

    @_effects(readonly)
    private static func formatRdffr(_ m: Mnemonic, _ ops: [Operand]) -> String {
        // Unpredicated form has one operand; predicated has two (Pd, Pg/z).
        if ops.count == 1 {
            return "\(name(m)) \(pred(ops, 0))"
        }
        return "\(name(m)) \(pred(ops, 0)), \(pred(ops, 1))"
    }

    @_effects(readonly)
    private static func formatCountPredicate(_ m: Mnemonic, _ ops: [Operand]) -> String {
        // Vector: [Zdn.T, Pm.T]. Scalar: [Rdn, Pm.T] or signed-32 [Xdn, Pm.T, Wdn].
        if case .scalableVector = operand(ops, 0) {
            return "\(name(m)) \(scalableVectorText(ops, 0)), \(pred(ops, 1))"
        }
        if ops.count >= 3 {
            return "\(name(m)) \(reg(ops, 0)), \(pred(ops, 1)), \(reg(ops, 2))"
        }
        return "\(name(m)) \(reg(ops, 0)), \(pred(ops, 1))"
    }

    @_effects(readonly)
    private static func formatElementCount(_ m: Mnemonic, _ ops: [Operand], destCount: Int) -> String {
        // dest operands (1 scalar, or 1 scalar + 1 W-source-view for signed-32,
        // or 1 vector) then the pattern/mul with the 3-tier elision ladder.
        var head = ""
        if destCount == 2 {
            head = "\(reg(ops, 0)), \(reg(ops, 1))"
        } else if case .scalableVector = operand(ops, 0) {
            head = scalableVectorText(ops, 0)
        } else {
            head = reg(ops, 0)
        }
        let patIndex = destCount
        guard case let .svePredicatePattern(pat) = operand(ops, patIndex) else {
            return "\(name(m)) \(head)"
        }
        let mulPresent = pat.multiplier != 1
        if SVEPatternName.isAll(pat.raw), !mulPresent {
            return "\(name(m)) \(head)" // drop `all` when it would be trailing
        }
        if !mulPresent {
            return "\(name(m)) \(head), \(SVEPatternName.text(pat.raw))"
        }
        return "\(name(m)) \(head), \(SVEPatternName.text(pat.raw)), mul #\(pat.multiplier)"
    }

    @_effects(readonly)
    private static func formatMovprfx(_ m: Mnemonic, _ ops: [Operand]) -> String {
        // Unpredicated: [Zd, Zn]. Predicated: [Zd.T, Pg/{z,m}, Zn.T].
        if ops.count == 2 {
            return "\(name(m)) \(scalableVectorText(ops, 0)), \(scalableVectorText(ops, 1))"
        }
        return "\(name(m)) \(scalableVectorText(ops, 0)), \(pred(ops, 1)), \(scalableVectorText(ops, 2))"
    }

    /// The number of leading register operands before the pattern for an
    /// element-count form: 2 for a signed-32 saturating scalar (X dest + W
    /// source-view), 1 otherwise.
    @_effects(readonly)
    private static func elementCountDestCount(_ ops: [Operand]) -> Int {
        if ops.count >= 2, case .register = ops[0], case .register = ops[1] {
            return 2
        }
        return 1
    }

    // MARK: operand renderers

    /// A predicate operand: `p<n>` + `.<T>` if sized + `/z`|`/m`.
    @_effects(readonly)
    private static func pred(_ ops: [Operand], _ i: Int) -> String {
        guard case let .scalablePredicate(p) = operand(ops, i) else { return "?p" }
        var s = "p\(p.registerIndex)"
        if let el = p.element { s += ".\(elementSuffix(el))" }
        switch p.qualifier {
        case .zeroing: s += "/z"
        case .merging: s += "/m"
        case .none: break
        }
        return s
    }

    @_effects(readonly)
    private static func scalableVectorText(_ ops: [Operand], _ i: Int) -> String {
        guard case let .scalableVector(v) = operand(ops, i) else { return "?z" }
        if let el = v.element { return "z\(v.registerIndex).\(elementSuffix(el))" }
        return "z\(v.registerIndex)"
    }

    @_effects(readonly)
    private static func reg(_ ops: [Operand], _ i: Int) -> String {
        guard case let .register(r) = operand(ops, i) else { return "?r" }
        return registerText(r)
    }

    @_effects(readonly)
    private static func imm(_ ops: [Operand], _ i: Int) -> String {
        switch operand(ops, i) {
        case let .immediate(value, _): "#\(value)"
        case let .unsignedImmediate(value, _): "#\(value)"
        default: "?#"
        }
    }

    /// An INDEX start/step operand — either a register or a signed immediate.
    @_effects(readonly)
    private static func indexOperand(_ ops: [Operand], _ i: Int) -> String {
        switch operand(ops, i) {
        case let .register(r): registerText(r)
        case let .immediate(value, _): "#\(value)"
        default: "?idx"
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func operand(_ ops: [Operand], _ i: Int) -> Operand {
        (i >= 0 && i < ops.count) ? ops[i] : .immediate(value: 0, width: 0)
    }

    @_effects(readonly)
    private static func elementSuffix(_ s: ScalarSize) -> String {
        switch s {
        case .b: "b"
        case .h: "h"
        case .s: "s"
        case .d: "d"
        case .q: "q"
        }
    }

    @_effects(readonly)
    private static func registerText(_ r: RegisterRef) -> String {
        switch (r.canonicalIndex, r.role, r.width) {
        case (31, .stackPointer, .x64): return "sp"
        case (31, .stackPointer, .w32): return "wsp"
        case (31, .zeroRegister, .x64): return "xzr"
        case (31, .zeroRegister, .w32): return "wzr"
        case (31, .general, _): return r.width == .x64 ? "xzr" : "wzr"
        default:
            let n = r.canonicalIndex
            if n < 31 { return r.width == .x64 ? "x\(n)" : "w\(n)" }
            return "?\(n)"
        }
    }

    // MARK: name table

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> String {
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
        default: "?\(m.rawValue)"
        }
    }
}

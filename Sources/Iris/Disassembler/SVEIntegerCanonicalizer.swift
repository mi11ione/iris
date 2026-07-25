// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer for SVE-integer — SVE / SVE2 integer. Renders a decoded
// record to llvm-mc-compatible disassembly text (the validator's parity
// oracle over the full op0=2 in-scope space). Because every SVE-integer decoder
// emits a fully-structured operand list (element sizes, predicate role and
// qualifier, register widths all captured on the operands), rendering is
// generic: the mnemonic text followed by the comma-joined operand renderings.
// The per-operand renderer applies the rules — governing predicate
// bare, result predicate suffixed, scalar SIMD/GPR widths, ADR bracket form.

/// Canonical llvm-mc-compatible disassembly text for an SVE integer record.
/// A scalable-tier hole never reaches here: the text router renders it as
/// `.long` before dispatching.
enum SVEIntegerCanonicalizer {
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        let mnemonic = name(instruction.mnemonic)
        if Array(instruction.operands).isEmpty { return mnemonic }
        var parts: [String] = []
        parts.reserveCapacity(Array(instruction.operands).count)
        for op in Array(instruction.operands) {
            parts.append(render(op, instruction.mnemonic))
        }
        return mnemonic + " " + parts.joined(separator: ", ")
    }

    // MARK: per-operand rendering

    @_effects(readonly)
    private static func render(_ op: Operand, _ mnemonic: Mnemonic) -> String {
        switch op {
        case let .scalableVector(v):
            var s = "z\(v.registerIndex)"
            if let el = v.element { s += ".\(suffix(el))" }
            if let idx = v.elementIndex { s += "[\(idx)]" }
            return s
        case let .scalablePredicate(p):
            // A governing predicate renders bare (`p0/m`); only a result predicate
            // carries an element suffix (`p0.s`) rule 2.
            var s = "p\(p.registerIndex)"
            if p.role == .result, let el = p.element { s += ".\(suffix(el))" }
            switch p.qualifier {
            case .zeroing: s += "/z"
            case .merging: s += "/m"
            case .none: break
            }
            return s
        case let .scalableVectorGroup(g):
            // llvm-mc pads the braces (`{ z2.s, z3.s }`); normalizeDisassembly
            // collapses runs of whitespace but does not remove it, so the spaces
            // are part of the canonical text.
            var members: [String] = []
            members.reserveCapacity(Int(g.count))
            let dot = g.element.map { ".\(suffix($0))" } ?? ""
            for j in 0 ..< g.count {
                members.append("z\(g.memberIndex(j))\(dot)")
            }
            return "{ " + members.joined(separator: ", ") + " }"
        case let .register(r): return registerText(r)
        case let .vectorRegister(v):
            // Reductions write either a scalar of the element width (`smaxv b0`) or,
            // for the quadword forms, a whole NEON vector (`addqv v0.16b`).
            switch v.view {
            case let .scalar(size): return "\(scalarPrefix(size))\(v.registerIndex)"
            case let .full(arrangement): return "v\(v.registerIndex).\(arrangementText(arrangement))"
            default: return "?v\(v.registerIndex)"
            }
        // Signed immediates (compares, DUP/CPY moves, rotations, shift amounts)
        // always print decimal. The logical-immediate family never reaches here —
        // it carries its value as `.unsignedImmediate`.
        case let .immediate(value, _): return "#\(value)"
        case let .unsignedImmediate(value, width): return unsignedImmediateText(value, width: width, mnemonic: mnemonic)
        case let .shiftAmount(kind, amount): return "\(shiftKind(kind)) #\(amount)"
        case let .scalableMemory(mem): return renderMemory(mem)
        default: return "?op"
        }
    }

    @_effects(readonly)
    private static func renderMemory(_ mem: ScalableMemoryOperand) -> String {
        guard case let .vector(base) = mem.base, let index = mem.index else { return "?mem" }
        let baseT = base.element.map { ".\(suffix($0))" } ?? ""
        let idxT = index.element.map { ".\(suffix($0))" } ?? ""
        var extend = ""
        switch mem.indexExtend {
        case .uxtw: extend = ", uxtw" + (mem.scaleShift > 0 ? " #\(mem.scaleShift)" : "")
        case .sxtw: extend = ", sxtw" + (mem.scaleShift > 0 ? " #\(mem.scaleShift)" : "")
        case .lsl: extend = mem.scaleShift > 0 ? ", lsl #\(mem.scaleShift)" : "" // packed lsl #0 is elided
        default: break
        }
        return "[z\(base.registerIndex)\(baseT), z\(index.registerIndex)\(idxT)\(extend)]"
    }

    @_effects(readonly)
    private static func registerText(_ r: RegisterRef) -> String {
        if r.canonicalIndex == 31 {
            if r.isStackPointer { return r.width == .x64 ? "sp" : "wsp" }
            if r.isZeroRegister { return r.width == .x64 ? "xzr" : "wzr" }
        }
        if r.isSIMD { return "?s\(r.canonicalIndex)" }
        return (r.width == .x64 ? "x" : "w") + "\(r.canonicalIndex)"
    }

    @inline(__always) @_effects(readonly)
    private static func isLogicalImmediate(_ m: Mnemonic) -> Bool {
        m == .and || m == .eor || m == .orr || m == .dupm
    }

    /// Unsigned-immediate text. AND/EOR/ORR/DUPM print the per-element
    /// value in hex. A DUPM→`mov` follows llvm's `printSVELogicalImm`: the value
    /// sign-extended from its element width prints as signed decimal when it fits
    /// int16, else the raw value prints as unsigned decimal when it fits uint16,
    /// else hex. Every other mnemonic prints plain unsigned decimal (compare imm7).
    @inline(__always) @_effects(readonly)
    private static func unsignedImmediateText(_ value: UInt64, width: UInt8, mnemonic: Mnemonic) -> String {
        if isLogicalImmediate(mnemonic) { return "#0x" + String(value, radix: 16) }
        if mnemonic == .mov {
            let signed = signExtend(value, width: UInt64(width))
            if signed >= -32768, signed <= 32767 { return "#\(signed)" }
            if value <= 0xFFFF { return "#\(value)" }
            return "#0x" + String(value, radix: 16)
        }
        return "#\(value)"
    }

    @inline(__always) @_effects(readonly)
    private static func signExtend(_ value: UInt64, width: UInt64) -> Int64 {
        if width >= 64 { return Int64(bitPattern: value) }
        let shift = UInt64(64) - width
        return Int64(bitPattern: value << shift) >> Int64(shift)
    }

    @inline(__always) @_effects(readonly)
    private static func shiftKind(_ k: ShiftKind) -> String {
        switch k { case .lsl: "lsl"; case .lsr: "lsr"; case .asr: "asr"; case .ror: "ror"; case .msl: "msl" }
    }

    @inline(__always) @_effects(readonly)
    private static func suffix(_ s: ScalarSize) -> String {
        switch s { case .b: "b"; case .h: "h"; case .s: "s"; case .d: "d"; case .q: "q" }
    }

    @inline(__always) @_effects(readonly)
    private static func scalarPrefix(_ s: ScalarSize) -> String {
        switch s { case .b: "b"; case .h: "h"; case .s: "s"; case .d: "d"; case .q: "q" }
    }

    /// The NEON arrangement suffix. Only the four full-width (128-bit) forms are
    /// reachable from SVE-integer — the quadword reductions' destination.
    @inline(__always) @_effects(readonly)
    private static func arrangementText(_ a: VectorArrangement) -> String {
        switch a {
        case .b8: "8b"
        case .b16: "16b"
        case .h2: "2h"
        case .h4: "4h"
        case .h8: "8h"
        case .s2: "2s"
        case .s4: "4s"
        case .d1: "1d"
        case .d2: "2d"
        case .q1: "1q"
        }
    }

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> String {
        switch m {
        case .abs: "abs"
        case .adclb: "adclb"
        case .adclt: "adclt"
        case .add: "add"
        case .addhnb: "addhnb"
        case .addhnt: "addhnt"
        case .addp: "addp"
        case .addpt: "addpt"
        case .addqp: "addqp"
        case .addqv: "addqv"
        case .addsubp: "addsubp"
        case .adr: "adr"
        case .and: "and"
        case .andqv: "andqv"
        case .andv: "andv"
        case .asr: "asr"
        case .asrd: "asrd"
        case .asrr: "asrr"
        case .bcax: "bcax"
        case .bdep: "bdep"
        case .bext: "bext"
        case .bgrp: "bgrp"
        case .bic: "bic"
        case .bsl: "bsl"
        case .bsl1n: "bsl1n"
        case .bsl2n: "bsl2n"
        case .cadd: "cadd"
        case .cdot: "cdot"
        case .cls: "cls"
        case .clz: "clz"
        case .cmla: "cmla"
        case .cmpeq: "cmpeq"
        case .cmpge: "cmpge"
        case .cmpgt: "cmpgt"
        case .cmphi: "cmphi"
        case .cmphs: "cmphs"
        case .cmple: "cmple"
        case .cmplo: "cmplo"
        case .cmpls: "cmpls"
        case .cmplt: "cmplt"
        case .cmpne: "cmpne"
        case .cnot: "cnot"
        case .cnt: "cnt"
        case .dupm: "dupm"
        case .eor: "eor"
        case .eor3: "eor3"
        case .eorbt: "eorbt"
        case .eorqv: "eorqv"
        case .eortb: "eortb"
        case .eorv: "eorv"
        case .histcnt: "histcnt"
        case .histseg: "histseg"
        case .lsl: "lsl"
        case .lslr: "lslr"
        case .lsr: "lsr"
        case .lsrr: "lsrr"
        case .mad: "mad"
        case .madpt: "madpt"
        case .match: "match"
        case .mla: "mla"
        case .mlapt: "mlapt"
        case .mls: "mls"
        case .mov: "mov"
        case .msb: "msb"
        case .mul: "mul"
        case .nbsl: "nbsl"
        case .neg: "neg"
        case .nmatch: "nmatch"
        case .not: "not"
        case .orqv: "orqv"
        case .orr: "orr"
        case .orv: "orv"
        case .pmul: "pmul"
        case .pmullb: "pmullb"
        case .pmullt: "pmullt"
        case .raddhnb: "raddhnb"
        case .raddhnt: "raddhnt"
        case .rshrnb: "rshrnb"
        case .rshrnt: "rshrnt"
        case .rsubhnb: "rsubhnb"
        case .rsubhnt: "rsubhnt"
        case .saba: "saba"
        case .sabal: "sabal"
        case .sabalb: "sabalb"
        case .sabalt: "sabalt"
        case .sabd: "sabd"
        case .sabdlb: "sabdlb"
        case .sabdlt: "sabdlt"
        case .sadalp: "sadalp"
        case .saddlb: "saddlb"
        case .saddlbt: "saddlbt"
        case .saddlt: "saddlt"
        case .saddv: "saddv"
        case .saddwb: "saddwb"
        case .saddwt: "saddwt"
        case .sbclb: "sbclb"
        case .sbclt: "sbclt"
        case .sclamp: "sclamp"
        case .sdiv: "sdiv"
        case .sdivr: "sdivr"
        case .sdot: "sdot"
        case .shadd: "shadd"
        case .shrnb: "shrnb"
        case .shrnt: "shrnt"
        case .shsub: "shsub"
        case .shsubr: "shsubr"
        case .sli: "sli"
        case .smax: "smax"
        case .smaxp: "smaxp"
        case .smaxqv: "smaxqv"
        case .smaxv: "smaxv"
        case .smin: "smin"
        case .sminp: "sminp"
        case .sminqv: "sminqv"
        case .sminv: "sminv"
        case .smlalb: "smlalb"
        case .smlalt: "smlalt"
        case .smlslb: "smlslb"
        case .smlslt: "smlslt"
        case .smmla: "smmla"
        case .smulh: "smulh"
        case .smullb: "smullb"
        case .smullt: "smullt"
        case .sqabs: "sqabs"
        case .sqadd: "sqadd"
        case .sqcadd: "sqcadd"
        case .sqcvtn: "sqcvtn"
        case .sqcvtun: "sqcvtun"
        case .sqdmlalb: "sqdmlalb"
        case .sqdmlalbt: "sqdmlalbt"
        case .sqdmlalt: "sqdmlalt"
        case .sqdmlslb: "sqdmlslb"
        case .sqdmlslbt: "sqdmlslbt"
        case .sqdmlslt: "sqdmlslt"
        case .sqdmulh: "sqdmulh"
        case .sqdmullb: "sqdmullb"
        case .sqdmullt: "sqdmullt"
        case .sqneg: "sqneg"
        case .sqrdcmlah: "sqrdcmlah"
        case .sqrdmlah: "sqrdmlah"
        case .sqrdmlsh: "sqrdmlsh"
        case .sqrdmulh: "sqrdmulh"
        case .sqrshl: "sqrshl"
        case .sqrshlr: "sqrshlr"
        case .sqrshrn: "sqrshrn"
        case .sqrshrnb: "sqrshrnb"
        case .sqrshrnt: "sqrshrnt"
        case .sqrshrun: "sqrshrun"
        case .sqrshrunb: "sqrshrunb"
        case .sqrshrunt: "sqrshrunt"
        case .sqshl: "sqshl"
        case .sqshlr: "sqshlr"
        case .sqshlu: "sqshlu"
        case .sqshrn: "sqshrn"
        case .sqshrnb: "sqshrnb"
        case .sqshrnt: "sqshrnt"
        case .sqshrun: "sqshrun"
        case .sqshrunb: "sqshrunb"
        case .sqshrunt: "sqshrunt"
        case .sqsub: "sqsub"
        case .sqsubr: "sqsubr"
        case .sqxtnb: "sqxtnb"
        case .sqxtnt: "sqxtnt"
        case .sqxtunb: "sqxtunb"
        case .sqxtunt: "sqxtunt"
        case .srhadd: "srhadd"
        case .sri: "sri"
        case .srshl: "srshl"
        case .srshlr: "srshlr"
        case .srshr: "srshr"
        case .srsra: "srsra"
        case .sshllb: "sshllb"
        case .sshllt: "sshllt"
        case .ssra: "ssra"
        case .ssublb: "ssublb"
        case .ssublbt: "ssublbt"
        case .ssublt: "ssublt"
        case .ssubltb: "ssubltb"
        case .ssubwb: "ssubwb"
        case .ssubwt: "ssubwt"
        case .sub: "sub"
        case .subhnb: "subhnb"
        case .subhnt: "subhnt"
        case .subp: "subp"
        case .subpt: "subpt"
        case .subr: "subr"
        case .sudot: "sudot"
        case .suqadd: "suqadd"
        case .sxtb: "sxtb"
        case .sxth: "sxth"
        case .sxtw: "sxtw"
        case .uaba: "uaba"
        case .uabal: "uabal"
        case .uabalb: "uabalb"
        case .uabalt: "uabalt"
        case .uabd: "uabd"
        case .uabdlb: "uabdlb"
        case .uabdlt: "uabdlt"
        case .uadalp: "uadalp"
        case .uaddlb: "uaddlb"
        case .uaddlt: "uaddlt"
        case .uaddv: "uaddv"
        case .uaddwb: "uaddwb"
        case .uaddwt: "uaddwt"
        case .uclamp: "uclamp"
        case .udiv: "udiv"
        case .udivr: "udivr"
        case .udot: "udot"
        case .uhadd: "uhadd"
        case .uhsub: "uhsub"
        case .uhsubr: "uhsubr"
        case .umax: "umax"
        case .umaxp: "umaxp"
        case .umaxqv: "umaxqv"
        case .umaxv: "umaxv"
        case .umin: "umin"
        case .uminp: "uminp"
        case .uminqv: "uminqv"
        case .uminv: "uminv"
        case .umlalb: "umlalb"
        case .umlalt: "umlalt"
        case .umlslb: "umlslb"
        case .umlslt: "umlslt"
        case .ummla: "ummla"
        case .umulh: "umulh"
        case .umullb: "umullb"
        case .umullt: "umullt"
        case .uqadd: "uqadd"
        case .uqcvtn: "uqcvtn"
        case .uqrshl: "uqrshl"
        case .uqrshlr: "uqrshlr"
        case .uqrshrn: "uqrshrn"
        case .uqrshrnb: "uqrshrnb"
        case .uqrshrnt: "uqrshrnt"
        case .uqshl: "uqshl"
        case .uqshlr: "uqshlr"
        case .uqshrn: "uqshrn"
        case .uqshrnb: "uqshrnb"
        case .uqshrnt: "uqshrnt"
        case .uqsub: "uqsub"
        case .uqsubr: "uqsubr"
        case .uqxtnb: "uqxtnb"
        case .uqxtnt: "uqxtnt"
        case .urecpe: "urecpe"
        case .urhadd: "urhadd"
        case .urshl: "urshl"
        case .urshlr: "urshlr"
        case .urshr: "urshr"
        case .ursqrte: "ursqrte"
        case .ursra: "ursra"
        case .usdot: "usdot"
        case .ushllb: "ushllb"
        case .ushllt: "ushllt"
        case .usmmla: "usmmla"
        case .usqadd: "usqadd"
        case .usra: "usra"
        case .usublb: "usublb"
        case .usublt: "usublt"
        case .usubwb: "usubwb"
        case .usubwt: "usubwt"
        case .uxtb: "uxtb"
        case .uxth: "uxth"
        case .uxtw: "uxtw"
        case .xar: "xar"
        default: "?\(m.rawValue)"
        }
    }
}

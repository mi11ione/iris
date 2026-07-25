// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonical llvm-mc-parity text for SME2 multi-vector
// records. Mirrors the SVE/SME canonicalizer conventions: lowercase,
// `, `-joined operands. A scalable-tier hole never reaches here — the text
// router renders it as `.long` before dispatching. The SME2-specific rules (spec,
// probe-pinned against llvm-mc 22.1.4): multi-vector groups render
// `{ z0.s, z1.s }` (pair, comma), `{ z0.s - z3.s }` (4-way consecutive, dash)
// or fully-listed strided/wrapping; ZA-array operands carry an optional
// `off:hi` range and `, vgx2`/`, vgx4` group suffix; predicate-as-counter
// registers render `pn<n>`; the vector-length multiplier renders `vlx2`/
// `vlx4`; ZT0 renders `zt0` (bare or `zt0[off]`); memory index register
// `xzr` is printed (unlike SME-core's tile loads).

/// Formats SME2 records exactly as llvm-mc renders them.
enum SME2Canonicalizer {
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        // ZERO of the ZT0 register renders a braced list; the ZA-array ZERO
        // forms render their operand normally.
        if instruction.mnemonic == .zero, Array(instruction.operands).count == 1,
           case .zt0 = Array(instruction.operands)[0] { return "zero { zt0 }" }
        // The LUTv2 vector MOVT renders its ZT0 index with `, mul vl`
        // (distinct from the scalar MOVT's `zt0[off]`); it is the movt form
        // with a Z source.
        if instruction.mnemonic == .movt, Array(instruction.operands).count == 2,
           case let .zt0(index) = Array(instruction.operands)[0],
           case let .scalableVector(v) = Array(instruction.operands)[1]
        {
            let zt0Text = index.map { "zt0[\($0), mul vl]" } ?? "zt0"
            return "movt \(zt0Text), z\(v.registerIndex)"
        }
        let mnemonic = name(instruction.mnemonic)
        if Array(instruction.operands).isEmpty { return mnemonic }
        var parts: [String] = []
        parts.reserveCapacity(Array(instruction.operands).count)
        for op in Array(instruction.operands) {
            parts.append(render(op))
        }
        return mnemonic + " " + parts.joined(separator: ", ")
    }

    // MARK: per-operand rendering

    @_effects(readonly)
    private static func render(_ op: Operand) -> String {
        switch op {
        case let .scalableVectorGroup(g): groupText(g)
        case let .predicateGroup(first, count, element): predicateGroupText(first, count, element)
        case let .zaArrayVector(v): zaArrayText(v)
        case let .zaTile(index, element): zaTileText(index, element)
        case let .zaTileSlice(s): tileSliceText(s)
        case let .zt0(index): index.map { "zt0[\($0)]" } ?? "zt0"
        case let .vectorLengthMultiplier(n): "vlx\(n)"
        case let .scalablePredicate(p): predicateText(p)
        case let .scalableVector(v): vectorText(v)
        case let .scalableMemory(m): memoryText(m)
        case let .register(r): gpr64(r)
        case let .immediate(value, _): "#\(value)"
        case let .unsignedImmediate(value, _): "#\(value)"
        default: "?"
        }
    }

    // MARK: groups

    @_effects(readonly)
    private static func groupText(_ g: ScalableVectorGroup) -> String {
        let dot = g.element.map { ".\(suffix($0))" } ?? ""
        let idx = g.elementIndex.map { "[\($0)]" } ?? ""
        if g.count >= 3, g.layout == .consecutive, Int(g.firstIndex) + Int(g.count) - 1 <= 31 {
            let last = g.firstIndex &+ g.count &- 1
            return "{ z\(g.firstIndex)\(dot) - z\(last)\(dot) }\(idx)"
        }
        var members: [String] = []
        members.reserveCapacity(Int(g.count))
        for j in 0 ..< g.count {
            members.append("z\(g.memberIndex(j))\(dot)")
        }
        return "{ " + members.joined(separator: ", ") + " }\(idx)"
    }

    @_effects(readonly)
    private static func predicateGroupText(_ first: UInt8, _ count: UInt8, _ element: ScalarSize) -> String {
        var members: [String] = []
        members.reserveCapacity(Int(count))
        for j in 0 ..< count {
            members.append("p\((first &+ j) & 0xF).\(suffix(element))")
        }
        return "{ " + members.joined(separator: ", ") + " }"
    }

    // MARK: ZA operands

    @_effects(readonly)
    private static func zaArrayText(_ v: ZAArrayVectorOperand) -> String {
        let suffixText = v.element.map { ".\(suffix($0))" } ?? ""
        var index = "\(v.offset)"
        if let hi = v.offsetHigh { index += ":\(hi)" }
        let vg = switch v.group {
        case .vgx2: ", vgx2"
        case .vgx4: ", vgx4"
        case .none: ""
        }
        return "za\(suffixText)[\(selectText(v.selectRegister)), \(index)\(vg)]"
    }

    @_effects(readonly)
    private static func zaTileText(_ index: UInt8, _ element: ScalarSize?) -> String {
        guard let element else { return "za" }
        return "za\(index).\(suffix(element))"
    }

    @_effects(readonly)
    private static func tileSliceText(_ s: ZATileSliceOperand) -> String {
        let dir = s.direction == .vertical ? "v" : "h"
        var index = "\(s.offset)"
        if let hi = s.offsetHigh { index += ":\(hi)" }
        return "za\(s.tileIndex)\(dir).\(suffix(s.element))[\(selectText(s.selectRegister)), \(index)]"
    }

    // MARK: predicates / vectors

    @_effects(readonly)
    private static func predicateText(_ p: ScalablePredicateRef) -> String {
        var s = (p.isCounter ? "pn" : "p") + "\(p.registerIndex)"
        if let el = p.element { s += ".\(suffix(el))" }
        if let sel = p.selectRegister {
            s += "[\(selectText(sel)), \(p.elementIndex ?? 0)]"
        } else if let idx = p.elementIndex {
            s += "[\(idx)]"
        }
        switch p.qualifier {
        case .zeroing: s += "/z"
        case .merging: s += "/m"
        case .none: break
        }
        return s
    }

    @_effects(readonly)
    private static func vectorText(_ v: ScalableVectorRef) -> String {
        var s = "z\(v.registerIndex)"
        if let el = v.element { s += ".\(suffix(el))" }
        if let idx = v.elementIndex { s += "[\(idx)]" }
        return s
    }

    @_effects(readonly)
    private static func memoryText(_ m: ScalableMemoryOperand) -> String {
        var s = "["
        switch m.base {
        case let .gpr(r): s += gpr64(r)
        case let .vector(v): s += "z\(v.registerIndex)" + (v.element.map { ".\(suffix($0))" } ?? "")
        }
        if let si = m.scalarIndex {
            s += ", " + gpr64(si)
            if m.scaleShift > 0 { s += ", lsl #\(m.scaleShift)" }
        }
        if m.displacement != 0 {
            s += ", #\(m.displacement)"
            if m.mulVL { s += ", mul vl" }
        }
        s += "]"
        return s
    }

    // MARK: register text

    @_effects(readonly)
    private static func selectText(_ r: RegisterRef) -> String {
        "w\(r.canonicalIndex)"
    }

    /// A 64-bit GPR renders `x<n>` / `sp` / `xzr` by role.
    @_effects(readonly)
    private static func gpr64(_ r: RegisterRef) -> String {
        if r.isStackPointer { return "sp" }
        if r.isZeroRegister { return "xzr" }
        return "x\(r.canonicalIndex)"
    }

    @inline(__always) @_effects(readonly)
    private static func suffix(_ s: ScalarSize) -> String {
        switch s { case .b: "b"; case .h: "h"; case .s: "s"; case .d: "d"; case .q: "q" }
    }

    /// The rendered spelling of a SME2 mnemonic (MOVA already resolved to
    /// `.mov`).
    @_effects(readonly)
    static func name(_ m: Mnemonic) -> String {
        switch m {
        case .mov: "mov"; case .movaz: "movaz"; case .movt: "movt"; case .zero: "zero"
        case .luti2: "luti2"; case .luti4: "luti4"; case .luti6: "luti6"
        case .add: "add"; case .sub: "sub"; case .sel: "sel"
        case .fadd: "fadd"; case .fsub: "fsub"; case .bfadd: "bfadd"; case .bfsub: "bfsub"
        case .fmla: "fmla"; case .fmls: "fmls"; case .bfmla: "bfmla"; case .bfmls: "bfmls"
        case .fmlal: "fmlal"; case .fmlsl: "fmlsl"; case .bfmlal: "bfmlal"; case .bfmlsl: "bfmlsl"
        case .smlal: "smlal"; case .smlsl: "smlsl"; case .umlal: "umlal"; case .umlsl: "umlsl"
        case .smlall: "smlall"; case .smlsll: "smlsll"; case .umlall: "umlall"; case .umlsll: "umlsll"
        case .usmlall: "usmlall"; case .sumlall: "sumlall"; case .fmlall: "fmlall"
        case .sdot: "sdot"; case .udot: "udot"; case .usdot: "usdot"; case .sudot: "sudot"
        case .fdot: "fdot"; case .bfdot: "bfdot"
        case .fvdot: "fvdot"; case .bfvdot: "bfvdot"; case .svdot: "svdot"; case .uvdot: "uvdot"
        case .suvdot: "suvdot"; case .usvdot: "usvdot"; case .fvdotb: "fvdotb"; case .fvdott: "fvdott"
        case .smax: "smax"; case .smin: "smin"; case .umax: "umax"; case .umin: "umin"
        case .fmax: "fmax"; case .fmin: "fmin"; case .fmaxnm: "fmaxnm"; case .fminnm: "fminnm"
        case .bfmax: "bfmax"; case .bfmin: "bfmin"; case .bfmaxnm: "bfmaxnm"; case .bfminnm: "bfminnm"
        case .famax: "famax"; case .famin: "famin"; case .fscale: "fscale"; case .bfscale: "bfscale"
        case .sqdmulh: "sqdmulh"; case .srshl: "srshl"; case .urshl: "urshl"
        case .zip: "zip"; case .uzp: "uzp"; case .sunpk: "sunpk"; case .uunpk: "uunpk"
        case .fmul: "fmul"; case .bfmul: "bfmul"
        case .fcvt: "fcvt"; case .fcvtn: "fcvtn"; case .fcvtl: "fcvtl"; case .bfcvt: "bfcvt"; case .bfcvtn: "bfcvtn"
        case .fcvtzs: "fcvtzs"; case .fcvtzu: "fcvtzu"; case .scvtf: "scvtf"; case .ucvtf: "ucvtf"
        case .f1cvt: "f1cvt"; case .f2cvt: "f2cvt"; case .f1cvtl: "f1cvtl"; case .f2cvtl: "f2cvtl"
        case .bf1cvt: "bf1cvt"; case .bf2cvt: "bf2cvt"; case .bf1cvtl: "bf1cvtl"; case .bf2cvtl: "bf2cvtl"
        case .sqcvt: "sqcvt"; case .uqcvt: "uqcvt"; case .sqcvtu: "sqcvtu"
        case .sqcvtn: "sqcvtn"; case .uqcvtn: "uqcvtn"; case .sqcvtun: "sqcvtun"
        case .frinta: "frinta"; case .frintm: "frintm"; case .frintn: "frintn"; case .frintp: "frintp"
        case .sqrshr: "sqrshr"; case .uqrshr: "uqrshr"; case .sqrshru: "sqrshru"
        case .sqrshrn: "sqrshrn"; case .uqrshrn: "uqrshrn"; case .sqrshrun: "sqrshrun"
        case .sclamp: "sclamp"; case .uclamp: "uclamp"; case .fclamp: "fclamp"; case .bfclamp: "bfclamp"
        case .ld1b: "ld1b"; case .ld1h: "ld1h"; case .ld1w: "ld1w"; case .ld1d: "ld1d"
        case .st1b: "st1b"; case .st1h: "st1h"; case .st1w: "st1w"; case .st1d: "st1d"
        case .ldnt1b: "ldnt1b"; case .ldnt1h: "ldnt1h"; case .ldnt1w: "ldnt1w"; case .ldnt1d: "ldnt1d"
        case .stnt1b: "stnt1b"; case .stnt1h: "stnt1h"; case .stnt1w: "stnt1w"; case .stnt1d: "stnt1d"
        case .ldr: "ldr"; case .str: "str"
        case .whilege: "whilege"; case .whilegt: "whilegt"; case .whilehi: "whilehi"; case .whilehs: "whilehs"
        case .whilele: "whilele"; case .whilelt: "whilelt"; case .whilelo: "whilelo"; case .whilels: "whilels"
        case .pext: "pext"; case .ptrue: "ptrue"; case .cntp: "cntp"; case .psel: "psel"
        case .firstp: "firstp"; case .lastp: "lastp"
        case .smopa: "smopa"; case .smops: "smops"; case .umopa: "umopa"; case .umops: "umops"
        case .fmopa: "fmopa"
        case .fmop4a: "fmop4a"; case .fmop4s: "fmop4s"; case .bfmop4a: "bfmop4a"; case .bfmop4s: "bfmop4s"
        case .smop4a: "smop4a"; case .smop4s: "smop4s"; case .umop4a: "umop4a"; case .umop4s: "umop4s"
        case .sumop4a: "sumop4a"; case .sumop4s: "sumop4s"; case .usmop4a: "usmop4a"; case .usmop4s: "usmop4s"
        case .ftmopa: "ftmopa"; case .bftmopa: "bftmopa"; case .stmopa: "stmopa"
        case .utmopa: "utmopa"; case .sutmopa: "sutmopa"; case .ustmopa: "ustmopa"
        default: ""
        }
    }
}

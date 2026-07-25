// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonical llvm-mc-parity text for SVE-permute/memory (SVE / SVE2 permute, memory,
// and crypto) records. Mirrors the SVE-predicate/SVE-integer/SVE-FP canonicalizer conventions:
// lowercase, `, `-joined operands. A scalable-tier hole never reaches here —
// the text router renders it as `.long` before dispatching. The
// SVE-permute/memory-specific rules
// are the memory-bracket composition (base + scalar/vector index +
// extend/scale + displacement + `mul vl`, dropping a zero displacement), the
// vector-group range form (`{ z0.b - z3.b }` for a contiguous ascending run of
// three or more, comma-list otherwise), and the prefetch-op naming ({0-5}/
// {8-13} named, {6,7,14,15} raw).

/// Formats SVE-permute/memory SVE permute / memory / crypto records exactly as llvm-mc
/// renders them.
enum SVEPermuteMemoryCanonicalizer {
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
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
        case let .scalableVector(v):
            var s = "z\(v.registerIndex)"
            if let el = v.element { s += ".\(suffix(el))" }
            if let idx = v.elementIndex { s += "[\(idx)]" }
            return s
        case let .scalablePredicate(p):
            var s = "p\(p.registerIndex)"
            if let el = p.element { s += ".\(suffix(el))" }
            if let idx = p.elementIndex { s += "[\(idx)]" }
            switch p.qualifier {
            case .zeroing: s += "/z"
            case .merging: s += "/m"
            case .none: break
            }
            return s
        case let .scalableVectorGroup(g):
            return groupText(g)
        case let .scalableMemory(m):
            return memoryText(m)
        case let .register(r):
            return registerText(r)
        case let .vectorRegister(v):
            switch v.view {
            case let .scalar(size): return "\(suffix(size))\(v.registerIndex)"
            default: return "?v\(v.registerIndex)"
            }
        case let .prefetchOperation(p):
            return prefetchText(p)
        case let .immediate(value, _):
            return "#\(value)"
        case let .unsignedImmediate(value, _):
            return "#\(value)"
        default:
            return "?"
        }
    }

    // MARK: multi-vector group

    /// `{ z0.b, z1.b }` for a pair, `{ z0.b - z3.b }` for a contiguous ascending
    /// run of three or more with no register-file wrap, else a comma list.
    @_effects(readonly)
    private static func groupText(_ g: ScalableVectorGroup) -> String {
        let dot = g.element.map { ".\(suffix($0))" } ?? ""
        if g.count >= 3, g.layout == .consecutive, Int(g.firstIndex) + Int(g.count) - 1 <= 31 {
            let last = g.firstIndex &+ g.count &- 1
            return "{ z\(g.firstIndex)\(dot) - z\(last)\(dot) }"
        }
        var members: [String] = []
        members.reserveCapacity(Int(g.count))
        for j in 0 ..< g.count {
            members.append("z\(g.memberIndex(j))\(dot)")
        }
        return "{ " + members.joined(separator: ", ") + " }"
    }

    // MARK: memory bracket (–8.5)

    @_effects(readonly)
    private static func memoryText(_ m: ScalableMemoryOperand) -> String {
        var s = "["
        switch m.base {
        case let .gpr(r): s += registerText64(r)
        case let .vector(v): s += "z\(v.registerIndex)" + (v.element.map { ".\(suffix($0))" } ?? "")
        }
        if let si = m.scalarIndex {
            s += ", " + registerText64(si)
            if m.scaleShift > 0 { s += ", lsl #\(m.scaleShift)" }
        } else if let vi = m.index {
            s += ", z\(vi.registerIndex)" + (vi.element.map { ".\(suffix($0))" } ?? "")
            switch m.indexExtend {
            case .uxtw: s += ", uxtw"; if m.scaleShift > 0 { s += " #\(m.scaleShift)" }
            case .sxtw: s += ", sxtw"; if m.scaleShift > 0 { s += " #\(m.scaleShift)" }
            case .lsl: s += ", lsl #\(m.scaleShift)"
            default: break
            }
        }
        if m.displacement != 0 {
            s += ", #\(m.displacement)"
            if m.mulVL { s += ", mul vl" }
        }
        s += "]"
        return s
    }

    // MARK: prefetch op

    @_effects(readonly)
    private static func prefetchText(_ p: PrefetchOperation) -> String {
        switch p.rawValue {
        case 0: "pldl1keep"
        case 1: "pldl1strm"
        case 2: "pldl2keep"
        case 3: "pldl2strm"
        case 4: "pldl3keep"
        case 5: "pldl3strm"
        case 8: "pstl1keep"
        case 9: "pstl1strm"
        case 10: "pstl2keep"
        case 11: "pstl2strm"
        case 12: "pstl3keep"
        case 13: "pstl3strm"
        default: "#\(p.rawValue)"
        }
    }

    // MARK: register text

    @_effects(readonly)
    private static func registerText(_ r: RegisterRef) -> String {
        if r.canonicalIndex == 31 {
            if r.isStackPointer { return r.width == .x64 ? "sp" : "wsp" }
            if r.isZeroRegister { return r.width == .x64 ? "xzr" : "wzr" }
        }
        if r.isSIMD { return "?s\(r.canonicalIndex)" }
        return (r.width == .x64 ? "x" : "w") + "\(r.canonicalIndex)"
    }

    /// A GPR in an address always renders 64-bit (`xn`/`sp`).
    @_effects(readonly)
    private static func registerText64(_ r: RegisterRef) -> String {
        if r.canonicalIndex == 31 { return "sp" }
        return "x\(r.canonicalIndex)"
    }

    @inline(__always) @_effects(readonly)
    private static func suffix(_ s: ScalarSize) -> String {
        switch s { case .b: "b"; case .h: "h"; case .s: "s"; case .d: "d"; case .q: "q" }
    }

    // MARK: mnemonic text

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> String {
        switch m {
        // loads
        case .ld1b: "ld1b"; case .ld1h: "ld1h"; case .ld1w: "ld1w"; case .ld1d: "ld1d"
        case .ld1sb: "ld1sb"; case .ld1sh: "ld1sh"; case .ld1sw: "ld1sw"; case .ld1q: "ld1q"
        case .ldff1b: "ldff1b"; case .ldff1h: "ldff1h"; case .ldff1w: "ldff1w"; case .ldff1d: "ldff1d"
        case .ldff1sb: "ldff1sb"; case .ldff1sh: "ldff1sh"; case .ldff1sw: "ldff1sw"
        case .ldnf1b: "ldnf1b"; case .ldnf1h: "ldnf1h"; case .ldnf1w: "ldnf1w"; case .ldnf1d: "ldnf1d"
        case .ldnf1sb: "ldnf1sb"; case .ldnf1sh: "ldnf1sh"; case .ldnf1sw: "ldnf1sw"
        case .ldnt1b: "ldnt1b"; case .ldnt1h: "ldnt1h"; case .ldnt1w: "ldnt1w"; case .ldnt1d: "ldnt1d"
        case .ldnt1sb: "ldnt1sb"; case .ldnt1sh: "ldnt1sh"; case .ldnt1sw: "ldnt1sw"
        case .ld1rb: "ld1rb"; case .ld1rh: "ld1rh"; case .ld1rw: "ld1rw"; case .ld1rd: "ld1rd"
        case .ld1rsb: "ld1rsb"; case .ld1rsh: "ld1rsh"; case .ld1rsw: "ld1rsw"
        case .ld1rqb: "ld1rqb"; case .ld1rqh: "ld1rqh"; case .ld1rqw: "ld1rqw"; case .ld1rqd: "ld1rqd"
        case .ld1rob: "ld1rob"; case .ld1roh: "ld1roh"; case .ld1row: "ld1row"; case .ld1rod: "ld1rod"
        case .ld2b: "ld2b"; case .ld2h: "ld2h"; case .ld2w: "ld2w"; case .ld2d: "ld2d"; case .ld2q: "ld2q"
        case .ld3b: "ld3b"; case .ld3h: "ld3h"; case .ld3w: "ld3w"; case .ld3d: "ld3d"; case .ld3q: "ld3q"
        case .ld4b: "ld4b"; case .ld4h: "ld4h"; case .ld4w: "ld4w"; case .ld4d: "ld4d"; case .ld4q: "ld4q"
        case .ldr: "ldr"
        // stores
        case .st1b: "st1b"; case .st1h: "st1h"; case .st1w: "st1w"; case .st1d: "st1d"; case .st1q: "st1q"
        case .st2b: "st2b"; case .st2h: "st2h"; case .st2w: "st2w"; case .st2d: "st2d"; case .st2q: "st2q"
        case .st3b: "st3b"; case .st3h: "st3h"; case .st3w: "st3w"; case .st3d: "st3d"; case .st3q: "st3q"
        case .st4b: "st4b"; case .st4h: "st4h"; case .st4w: "st4w"; case .st4d: "st4d"; case .st4q: "st4q"
        case .stnt1b: "stnt1b"; case .stnt1h: "stnt1h"; case .stnt1w: "stnt1w"; case .stnt1d: "stnt1d"
        case .str: "str"
        // prefetch
        case .prfb: "prfb"; case .prfh: "prfh"; case .prfw: "prfw"; case .prfd: "prfd"
        // permute / move
        case .insr: "insr"; case .splice: "splice"; case .compact: "compact"; case .expand: "expand"
        case .lasta: "lasta"; case .lastb: "lastb"; case .clasta: "clasta"; case .clastb: "clastb"
        case .sunpkhi: "sunpkhi"; case .sunpklo: "sunpklo"; case .uunpkhi: "uunpkhi"; case .uunpklo: "uunpklo"
        case .punpkhi: "punpkhi"; case .punpklo: "punpklo"
        case .revb: "revb"; case .revh: "revh"; case .revw: "revw"; case .revd: "revd"
        case .rev: "rev"; case .rbit: "rbit"; case .sel: "sel"; case .ext: "ext"; case .mov: "mov"
        case .tbl: "tbl"; case .tbx: "tbx"
        case .zip1: "zip1"; case .zip2: "zip2"; case .uzp1: "uzp1"; case .uzp2: "uzp2"
        case .trn1: "trn1"; case .trn2: "trn2"
        case .dupq: "dupq"; case .extq: "extq"; case .tblq: "tblq"; case .tbxq: "tbxq"
        case .uzpq1: "uzpq1"; case .uzpq2: "uzpq2"; case .zipq1: "zipq1"; case .zipq2: "zipq2"
        case .pmov: "pmov"
        // crypto / lut
        case .aese: "aese"; case .aesd: "aesd"; case .aesmc: "aesmc"; case .aesimc: "aesimc"
        case .aesemc: "aesemc"; case .aesdimc: "aesdimc"
        case .sm4e: "sm4e"; case .sm4ekey: "sm4ekey"; case .rax1: "rax1"
        case .pmull: "pmull"; case .pmlal: "pmlal"
        case .luti2: "luti2"; case .luti4: "luti4"; case .luti6: "luti6"
        default: ""
        }
    }
}

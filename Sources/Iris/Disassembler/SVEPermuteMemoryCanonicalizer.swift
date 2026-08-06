// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Formats SVE-permute/memory SVE permute / memory / crypto records exactly as
/// llvm-mc renders them.
enum SVEPermuteMemoryCanonicalizer {
    /// The byte path.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if let spelling = name(instruction.mnemonic) { out.put(spelling) }
        let ops = instruction.operands
        if ops.isEmpty { return }
        out.put(UInt8(ascii: " "))
        for i in 0 ..< ops.count {
            if i > 0 { out.put(", ") }
            put(ops[i], into: &out)
        }
    }

    private static func put(_ op: Operand, into out: inout TextBytes) {
        switch op {
        case let .scalableVector(v):
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(v.registerIndex))
            if let el = v.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
            if let idx = v.elementIndex {
                out.put(UInt8(ascii: "["))
                out.putDecimal(UInt64(idx))
                out.put(UInt8(ascii: "]"))
            }
        case let .scalablePredicate(p):
            out.put(UInt8(ascii: "p"))
            out.putDecimal(UInt64(p.registerIndex))
            if let el = p.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
            if let idx = p.elementIndex {
                out.put(UInt8(ascii: "["))
                out.putDecimal(UInt64(idx))
                out.put(UInt8(ascii: "]"))
            }
            switch p.qualifier {
            case .zeroing: out.put("/z")
            case .merging: out.put("/m")
            case .none: break
            }
        case let .scalableVectorGroup(g):
            putGroup(g, into: &out)
        case let .scalableMemory(m):
            putMemory(m, into: &out)
        case let .register(r):
            putRegister(r, into: &out)
        case let .vectorRegister(v):
            switch v.view {
            case let .scalar(size):
                putSuffix(size, into: &out)
                out.putDecimal(UInt64(v.registerIndex))
            default:
                out.put("?v")
                out.putDecimal(UInt64(v.registerIndex))
            }
        case let .prefetchOperation(p):
            putPrefetch(p, into: &out)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        default:
            out.put("?")
        }
    }

    /// `{ z0.b, z1.b }` for a pair, `{ z0.b - z3.b }` for a contiguous
    /// ascending run of three or more with no register-file wrap, else a comma
    /// list.
    private static func putGroup(_ g: ScalableVectorGroup, into out: inout TextBytes) {
        if g.count >= 3, g.layout == .consecutive, Int(g.firstIndex) + Int(g.count) - 1 <= 31 {
            let last = g.firstIndex &+ g.count &- 1
            out.put("{ z")
            out.putDecimal(UInt64(g.firstIndex))
            putDot(g.element, into: &out)
            out.put(" - z")
            out.putDecimal(UInt64(last))
            putDot(g.element, into: &out)
            out.put(" }")
            return
        }
        out.put("{ ")
        for j in 0 ..< g.count {
            if j > 0 { out.put(", ") }
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(g.memberIndex(j)))
            putDot(g.element, into: &out)
        }
        out.put(" }")
    }

    @inline(__always)
    private static func putDot(_ element: ScalarSize?, into out: inout TextBytes) {
        guard let element else { return }
        out.put(UInt8(ascii: "."))
        putSuffix(element, into: &out)
    }

    private static func putMemory(_ m: ScalableMemoryOperand, into out: inout TextBytes) {
        out.put(UInt8(ascii: "["))
        switch m.base {
        case let .gpr(r):
            putRegister64(r, into: &out)
        case let .vector(v):
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(v.registerIndex))
            putDot(v.element, into: &out)
        }
        if let si = m.scalarIndex {
            out.put(", ")
            putRegister64(si, into: &out)
            if m.scaleShift > 0 {
                out.put(", lsl #")
                out.putDecimal(UInt64(m.scaleShift))
            }
        } else if let vi = m.index {
            out.put(", z")
            out.putDecimal(UInt64(vi.registerIndex))
            putDot(vi.element, into: &out)
            switch m.indexExtend {
            case .uxtw:
                out.put(", uxtw")
                if m.scaleShift > 0 {
                    out.put(" #")
                    out.putDecimal(UInt64(m.scaleShift))
                }
            case .sxtw:
                out.put(", sxtw")
                if m.scaleShift > 0 {
                    out.put(" #")
                    out.putDecimal(UInt64(m.scaleShift))
                }
            case .lsl:
                out.put(", lsl #")
                out.putDecimal(UInt64(m.scaleShift))
            default:
                break
            }
        }
        if m.displacement != 0 {
            out.put(", #")
            out.putDecimal(Int64(m.displacement))
            if m.mulVL { out.put(", mul vl") }
        }
        out.put(UInt8(ascii: "]"))
    }

    private static func putPrefetch(_ p: PrefetchOperation, into out: inout TextBytes) {
        switch p.rawValue {
        case 0: out.put("pldl1keep")
        case 1: out.put("pldl1strm")
        case 2: out.put("pldl2keep")
        case 3: out.put("pldl2strm")
        case 4: out.put("pldl3keep")
        case 5: out.put("pldl3strm")
        case 8: out.put("pstl1keep")
        case 9: out.put("pstl1strm")
        case 10: out.put("pstl2keep")
        case 11: out.put("pstl2strm")
        case 12: out.put("pstl3keep")
        case 13: out.put("pstl3strm")
        default:
            out.put(UInt8(ascii: "#"))
            out.putDecimal(UInt64(p.rawValue))
        }
    }

    private static func putRegister(_ r: RegisterRef, into out: inout TextBytes) {
        if r.canonicalIndex == 31 {
            if r.isStackPointer {
                out.put(r.width == .x64 ? "sp" : "wsp")
                return
            }
            if r.isZeroRegister {
                out.put(r.width == .x64 ? "xzr" : "wzr")
                return
            }
        }
        if r.isSIMD {
            out.put("?s")
            out.putDecimal(UInt64(r.canonicalIndex))
            return
        }
        out.put(r.width == .x64 ? "x" : "w")
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    /// A GPR in an address always renders 64-bit (`xn`/`sp`).
    @inline(__always)
    private static func putRegister64(_ r: RegisterRef, into out: inout TextBytes) {
        if r.canonicalIndex == 31 {
            out.put("sp")
            return
        }
        out.put(UInt8(ascii: "x"))
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    @inline(__always)
    private static func putSuffix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        case .d: out.put("d")
        case .q: out.put("q")
        }
    }

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
        switch m {
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
        case .st1b: "st1b"; case .st1h: "st1h"; case .st1w: "st1w"; case .st1d: "st1d"; case .st1q: "st1q"
        case .st2b: "st2b"; case .st2h: "st2h"; case .st2w: "st2w"; case .st2d: "st2d"; case .st2q: "st2q"
        case .st3b: "st3b"; case .st3h: "st3h"; case .st3w: "st3w"; case .st3d: "st3d"; case .st3q: "st3q"
        case .st4b: "st4b"; case .st4h: "st4h"; case .st4w: "st4w"; case .st4d: "st4d"; case .st4q: "st4q"
        case .stnt1b: "stnt1b"; case .stnt1h: "stnt1h"; case .stnt1w: "stnt1w"; case .stnt1d: "stnt1d"
        case .str: "str"
        case .prfb: "prfb"; case .prfh: "prfh"; case .prfw: "prfw"; case .prfd: "prfd"
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
        case .aese: "aese"; case .aesd: "aesd"; case .aesmc: "aesmc"; case .aesimc: "aesimc"
        case .aesemc: "aesemc"; case .aesdimc: "aesdimc"
        case .sm4e: "sm4e"; case .sm4ekey: "sm4ekey"; case .rax1: "rax1"
        case .pmull: "pmull"; case .pmlal: "pmlal"
        case .luti2: "luti2"; case .luti4: "luti4"; case .luti6: "luti6"
        default: ""
        }
    }
}

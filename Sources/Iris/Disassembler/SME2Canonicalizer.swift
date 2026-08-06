// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Formats SME2 records exactly as llvm-mc renders them.
enum SME2Canonicalizer {
    /// The byte path.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        let ops = instruction.operands
        if instruction.mnemonic == .zero, ops.count == 1, case .zt0 = ops[0] {
            out.put("zero { zt0 }")
            return
        }
        if instruction.mnemonic == .movt, ops.count == 2,
           case let .zt0(index) = ops[0],
           case let .scalableVector(v) = ops[1]
        {
            out.put("movt ")
            if let index {
                out.put("zt0[")
                out.putDecimal(UInt64(index))
                out.put(", mul vl]")
            } else {
                out.put("zt0")
            }
            out.put(", z")
            out.putDecimal(UInt64(v.registerIndex))
            return
        }
        if let spelling = name(instruction.mnemonic) { out.put(spelling) }
        if ops.isEmpty { return }
        out.put(UInt8(ascii: " "))
        for i in 0 ..< ops.count {
            if i > 0 { out.put(", ") }
            put(ops[i], into: &out)
        }
    }

    private static func put(_ op: Operand, into out: inout TextBytes) {
        switch op {
        case let .scalableVectorGroup(g): putGroup(g, into: &out)
        case let .predicateGroup(first, count, element):
            putPredicateGroup(first, count, element, into: &out)
        case let .zaArrayVector(v): putZAArray(v, into: &out)
        case let .zaTile(index, element): putZATile(index, element, into: &out)
        case let .zaTileSlice(s): putTileSlice(s, into: &out)
        case let .zt0(index):
            out.put("zt0")
            if let index {
                out.put(UInt8(ascii: "["))
                out.putDecimal(UInt64(index))
                out.put(UInt8(ascii: "]"))
            }
        case let .vectorLengthMultiplier(n):
            out.put("vlx")
            out.putDecimal(UInt64(n))
        case let .scalablePredicate(p): putPredicate(p, into: &out)
        case let .scalableVector(v): putVector(v, into: &out)
        case let .scalableMemory(m): putMemory(m, into: &out)
        case let .register(r): putGPR64(r, into: &out)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        default: out.put("?")
        }
    }

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
        } else {
            out.put("{ ")
            for j in 0 ..< g.count {
                if j > 0 { out.put(", ") }
                out.put(UInt8(ascii: "z"))
                out.putDecimal(UInt64(g.memberIndex(j)))
                putDot(g.element, into: &out)
            }
            out.put(" }")
        }
        if let idx = g.elementIndex {
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(idx))
            out.put(UInt8(ascii: "]"))
        }
    }

    private static func putPredicateGroup(
        _ first: UInt8, _ count: UInt8, _ element: ScalarSize, into out: inout TextBytes,
    ) {
        out.put("{ ")
        for j in 0 ..< count {
            if j > 0 { out.put(", ") }
            out.put(UInt8(ascii: "p"))
            out.putDecimal(UInt64((first &+ j) & 0xF))
            out.put(UInt8(ascii: "."))
            putSuffix(element, into: &out)
        }
        out.put(" }")
    }

    private static func putZAArray(_ v: ZAArrayVectorOperand, into out: inout TextBytes) {
        out.put("za")
        putDot(v.element, into: &out)
        out.put(UInt8(ascii: "["))
        putSelect(v.selectRegister, into: &out)
        out.put(", ")
        out.putDecimal(UInt64(v.offset))
        if let hi = v.offsetHigh {
            out.put(UInt8(ascii: ":"))
            out.putDecimal(UInt64(hi))
        }
        switch v.group {
        case .vgx2: out.put(", vgx2")
        case .vgx4: out.put(", vgx4")
        case .none: break
        }
        out.put(UInt8(ascii: "]"))
    }

    private static func putZATile(_ index: UInt8, _ element: ScalarSize?, into out: inout TextBytes) {
        guard let element else {
            out.put("za")
            return
        }
        out.put("za")
        out.putDecimal(UInt64(index))
        out.put(UInt8(ascii: "."))
        putSuffix(element, into: &out)
    }

    private static func putTileSlice(_ s: ZATileSliceOperand, into out: inout TextBytes) {
        out.put("za")
        out.putDecimal(UInt64(s.tileIndex))
        out.put(s.direction == .vertical ? "v" : "h")
        out.put(UInt8(ascii: "."))
        putSuffix(s.element, into: &out)
        out.put(UInt8(ascii: "["))
        putSelect(s.selectRegister, into: &out)
        out.put(", ")
        out.putDecimal(UInt64(s.offset))
        if let hi = s.offsetHigh {
            out.put(UInt8(ascii: ":"))
            out.putDecimal(UInt64(hi))
        }
        out.put(UInt8(ascii: "]"))
    }

    private static func putPredicate(_ p: ScalablePredicateRef, into out: inout TextBytes) {
        out.put(p.isCounter ? "pn" : "p")
        out.putDecimal(UInt64(p.registerIndex))
        putDot(p.element, into: &out)
        if let sel = p.selectRegister {
            out.put(UInt8(ascii: "["))
            putSelect(sel, into: &out)
            out.put(", ")
            out.putDecimal(UInt64(p.elementIndex ?? 0))
            out.put(UInt8(ascii: "]"))
        } else if let idx = p.elementIndex {
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(idx))
            out.put(UInt8(ascii: "]"))
        }
        switch p.qualifier {
        case .zeroing: out.put("/z")
        case .merging: out.put("/m")
        case .none: break
        }
    }

    private static func putVector(_ v: ScalableVectorRef, into out: inout TextBytes) {
        out.put(UInt8(ascii: "z"))
        out.putDecimal(UInt64(v.registerIndex))
        putDot(v.element, into: &out)
        if let idx = v.elementIndex {
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(idx))
            out.put(UInt8(ascii: "]"))
        }
    }

    private static func putMemory(_ m: ScalableMemoryOperand, into out: inout TextBytes) {
        out.put(UInt8(ascii: "["))
        switch m.base {
        case let .gpr(r):
            putGPR64(r, into: &out)
        case let .vector(v):
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(v.registerIndex))
            putDot(v.element, into: &out)
        }
        if let si = m.scalarIndex {
            out.put(", ")
            putGPR64(si, into: &out)
            if m.scaleShift > 0 {
                out.put(", lsl #")
                out.putDecimal(UInt64(m.scaleShift))
            }
        }
        if m.displacement != 0 {
            out.put(", #")
            out.putDecimal(Int64(m.displacement))
            if m.mulVL { out.put(", mul vl") }
        }
        out.put(UInt8(ascii: "]"))
    }

    @inline(__always)
    private static func putSelect(_ r: RegisterRef, into out: inout TextBytes) {
        out.put(UInt8(ascii: "w"))
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    /// A 64-bit GPR renders `x<n>` / `sp` / `xzr` by role.
    private static func putGPR64(_ r: RegisterRef, into out: inout TextBytes) {
        if r.isStackPointer {
            out.put("sp")
            return
        }
        if r.isZeroRegister {
            out.put("xzr")
            return
        }
        out.put(UInt8(ascii: "x"))
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    @inline(__always)
    private static func putDot(_ element: ScalarSize?, into out: inout TextBytes) {
        guard let element else { return }
        out.put(UInt8(ascii: "."))
        putSuffix(element, into: &out)
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

    /// The rendered spelling of a SME2 mnemonic (MOVA already resolved to
    /// `.mov`).
    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
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

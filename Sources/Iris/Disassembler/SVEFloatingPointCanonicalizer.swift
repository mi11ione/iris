// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonical llvm-mc-parity text for SVE-FP (SVE / SVE2 floating-
// point) records. Mirrors the SVE-predicate/SVE-integer canonicalizer conventions: lowercase,
// `, `-joined operands. A scalable-tier hole never reaches here — the text
// router renders it as `.long` before dispatching, and llvm-mc likewise emits
// nothing for rejected words. The one FP-specific rule is the immediate style split
// `fmov` renders the VFPExpandImm value as a signed 8-decimal
// fixed literal (`#2.12500000`, `#-13.00000000` — verified against the full
// imm8 space), while the arith-immediate family renders its exact constants
// short (`#0.5` / `#1.0` / `#2.0` / `#0.0`) and the compare-with-zero forms
// render the literal `#0.0`.

/// Formats SVE-FP records exactly as llvm-mc renders them.
enum SVEFloatingPointCanonicalizer {
    /// The byte path — rendered straight into a UTF-8 buffer.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        // This family's own table, not the global one: a mnemonic from
        // outside the group renders the `?<raw>` sentinel rather than the
        // spelling another family owns.
        if let spelling = name(instruction.mnemonic) {
            out.put(spelling)
        } else {
            out.put(UInt8(ascii: "?"))
            out.putDecimal(UInt64(instruction.mnemonic.rawValue))
        }
        let ops = instruction.operands
        if ops.isEmpty { return }
        out.put(UInt8(ascii: " "))
        for i in 0 ..< ops.count {
            if i > 0 { out.put(", ") }
            put(ops[i], instruction.mnemonic, into: &out)
        }
    }

    // MARK: per-operand rendering

    private static func put(_ op: Operand, _ mnemonic: Mnemonic, into out: inout TextBytes) {
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
            // A governing predicate renders bare (`p0/m`, or `p0` for the
            // reductions); only a result predicate carries an element suffix.
            out.put(UInt8(ascii: "p"))
            out.putDecimal(UInt64(p.registerIndex))
            if p.role == .result, let el = p.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
            switch p.qualifier {
            case .zeroing: out.put("/z")
            case .merging: out.put("/m")
            case .none: break
            }
        case let .scalableVectorGroup(g):
            // llvm-mc pads the braces (`{ z4.s, z5.s }`).
            out.put("{ ")
            for j in 0 ..< g.count {
                if j > 0 { out.put(", ") }
                out.put(UInt8(ascii: "z"))
                out.putDecimal(UInt64(g.memberIndex(j)))
                if let el = g.element {
                    out.put(UInt8(ascii: "."))
                    putSuffix(el, into: &out)
                }
            }
            out.put(" }")
        case let .vectorRegister(v):
            switch v.view {
            case let .scalar(size):
                putSuffix(size, into: &out)
                out.putDecimal(UInt64(v.registerIndex))
            case let .full(arrangement):
                out.put(UInt8(ascii: "v"))
                out.putDecimal(UInt64(v.registerIndex))
                out.put(UInt8(ascii: "."))
                putArrangement(arrangement, into: &out)
            case .element, .elementGroup, .lane:
                out.put("?v")
                out.putDecimal(UInt64(v.registerIndex))
            }
        case let .floatImmediate(bits, kind):
            putFloat(bits: bits, kind: kind, mnemonic: mnemonic, into: &out)
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

    /// The FP-immediate style split: `#0.0` for zero bits, the 8-decimal
    /// expanded form for `fmov`, and the short exact constants for the
    /// arith-immediate family.
    @inline(__always)
    private static func putFloat(
        bits: UInt64, kind: FloatImmediateKind, mnemonic: Mnemonic, into out: inout TextBytes,
    ) {
        if bits == 0 {
            out.put("#0.0")
            return
        }
        let value = switch kind {
        case .half: SIMDFPCanonicalizer.halfBitsToDouble(UInt16(truncatingIfNeeded: bits))
        case .single: Double(Float(bitPattern: UInt32(truncatingIfNeeded: bits)))
        case .double: Double(bitPattern: bits)
        }
        if mnemonic != .fmov {
            if value == 0.5 {
                out.put("#0.5")
                return
            }
            if value == 1.0 {
                out.put("#1.0")
                return
            }
            if value == 2.0 {
                out.put("#2.0")
                return
            }
        }
        out.put(UInt8(ascii: "#"))
        out.putString(SIMDFPCanonicalizer.fixedEightFractionText(value))
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

    @inline(__always)
    private static func putArrangement(_ a: VectorArrangement, into out: inout TextBytes) {
        switch a {
        case .b8: out.put("8b")
        case .b16: out.put("16b")
        case .h4: out.put("4h")
        case .h8: out.put("8h")
        case .s2: out.put("2s")
        case .s4: out.put("4s")
        case .d1: out.put("1d")
        case .d2: out.put("2d")
        case .q1: out.put("1q")
        case .h2: out.put("2h")
        }
    }

    // MARK: mnemonic text

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
        switch m {
        case .fabs: "fabs"
        case .fneg: "fneg"
        case .fadd: "fadd"
        case .fsub: "fsub"
        case .fsubr: "fsubr"
        case .fmul: "fmul"
        case .fmulx: "fmulx"
        case .fdiv: "fdiv"
        case .fdivr: "fdivr"
        case .fmax: "fmax"
        case .fmin: "fmin"
        case .fmaxnm: "fmaxnm"
        case .fminnm: "fminnm"
        case .fabd: "fabd"
        case .fscale: "fscale"
        case .famax: "famax"
        case .famin: "famin"
        case .faddp: "faddp"
        case .fmaxnmp: "fmaxnmp"
        case .fminnmp: "fminnmp"
        case .fmaxp: "fmaxp"
        case .fminp: "fminp"
        case .fmla: "fmla"
        case .fmls: "fmls"
        case .fnmla: "fnmla"
        case .fnmls: "fnmls"
        case .fmad: "fmad"
        case .fmsb: "fmsb"
        case .fnmad: "fnmad"
        case .fnmsb: "fnmsb"
        case .ftmad: "ftmad"
        case .ftsmul: "ftsmul"
        case .ftssel: "ftssel"
        case .fexpa: "fexpa"
        case .frecps: "frecps"
        case .frsqrts: "frsqrts"
        case .frecpe: "frecpe"
        case .frsqrte: "frsqrte"
        case .frecpx: "frecpx"
        case .fsqrt: "fsqrt"
        case .faddv: "faddv"
        case .fmaxnmv: "fmaxnmv"
        case .fminnmv: "fminnmv"
        case .fmaxv: "fmaxv"
        case .fminv: "fminv"
        case .fadda: "fadda"
        case .faddqv: "faddqv"
        case .fmaxnmqv: "fmaxnmqv"
        case .fminnmqv: "fminnmqv"
        case .fmaxqv: "fmaxqv"
        case .fminqv: "fminqv"
        case .fcmeq: "fcmeq"
        case .fcmge: "fcmge"
        case .fcmgt: "fcmgt"
        case .fcmne: "fcmne"
        case .fcmuo: "fcmuo"
        case .fcmle: "fcmle"
        case .fcmlt: "fcmlt"
        case .facge: "facge"
        case .facgt: "facgt"
        case .fcvt: "fcvt"
        case .fcvtx: "fcvtx"
        case .fcvtzs: "fcvtzs"
        case .fcvtzu: "fcvtzu"
        case .scvtf: "scvtf"
        case .ucvtf: "ucvtf"
        case .frinta: "frinta"
        case .frinti: "frinti"
        case .frintm: "frintm"
        case .frintn: "frintn"
        case .frintp: "frintp"
        case .frintx: "frintx"
        case .frintz: "frintz"
        case .frint32x: "frint32x"
        case .frint32z: "frint32z"
        case .frint64x: "frint64x"
        case .frint64z: "frint64z"
        case .flogb: "flogb"
        case .fcvtlt: "fcvtlt"
        case .fcvtnt: "fcvtnt"
        case .fcvtxnt: "fcvtxnt"
        case .bfcvt: "bfcvt"
        case .bfcvtnt: "bfcvtnt"
        case .fcadd: "fcadd"
        case .fcmla: "fcmla"
        case .fmov: "fmov"
        case .fdot: "fdot"
        case .bfdot: "bfdot"
        case .fmlalb: "fmlalb"
        case .fmlalt: "fmlalt"
        case .fmlslb: "fmlslb"
        case .fmlslt: "fmlslt"
        case .bfmlalb: "bfmlalb"
        case .bfmlalt: "bfmlalt"
        case .bfmlslb: "bfmlslb"
        case .bfmlslt: "bfmlslt"
        case .fmlallbb: "fmlallbb"
        case .fmlallbt: "fmlallbt"
        case .fmlalltb: "fmlalltb"
        case .fmlalltt: "fmlalltt"
        case .fmmla: "fmmla"
        case .bfmmla: "bfmmla"
        case .fclamp: "fclamp"
        case .bfclamp: "bfclamp"
        case .bfadd: "bfadd"
        case .bfsub: "bfsub"
        case .bfmul: "bfmul"
        case .bfmax: "bfmax"
        case .bfmin: "bfmin"
        case .bfmaxnm: "bfmaxnm"
        case .bfminnm: "bfminnm"
        case .bfmla: "bfmla"
        case .bfmls: "bfmls"
        case .bfscale: "bfscale"
        case .f1cvt: "f1cvt"
        case .f1cvtlt: "f1cvtlt"
        case .f2cvt: "f2cvt"
        case .f2cvtlt: "f2cvtlt"
        case .bf1cvt: "bf1cvt"
        case .bf1cvtlt: "bf1cvtlt"
        case .bf2cvt: "bf2cvt"
        case .bf2cvtlt: "bf2cvtlt"
        case .fcvtn: "fcvtn"
        case .fcvtnb: "fcvtnb"
        case .bfcvtn: "bfcvtn"
        case .fcvtzsn: "fcvtzsn"
        case .fcvtzun: "fcvtzun"
        case .scvtflt: "scvtflt"
        case .ucvtflt: "ucvtflt"
        default: nil
        }
    }
}

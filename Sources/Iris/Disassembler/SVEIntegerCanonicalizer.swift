// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical llvm-mc-compatible disassembly text for an SVE integer record.
enum SVEIntegerCanonicalizer {
    /// The byte path.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
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
        case let .register(r):
            putRegister(r, into: &out)
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
            default:
                out.put("?v")
                out.putDecimal(UInt64(v.registerIndex))
            }
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, width):
            putUnsignedImmediate(value, width: width, mnemonic: mnemonic, into: &out)
        case let .shiftAmount(kind, amount):
            putShiftKind(kind, into: &out)
            out.put(" #")
            out.putDecimal(UInt64(amount))
        case let .scalableMemory(mem):
            putMemory(mem, into: &out)
        default:
            out.put("?op")
        }
    }

    private static func putMemory(_ mem: ScalableMemoryOperand, into out: inout TextBytes) {
        guard case let .vector(base) = mem.base, let index = mem.index else {
            out.put("?mem")
            return
        }
        out.put("[z")
        out.putDecimal(UInt64(base.registerIndex))
        if let el = base.element {
            out.put(UInt8(ascii: "."))
            putSuffix(el, into: &out)
        }
        out.put(", z")
        out.putDecimal(UInt64(index.registerIndex))
        if let el = index.element {
            out.put(UInt8(ascii: "."))
            putSuffix(el, into: &out)
        }
        switch mem.indexExtend {
        case .uxtw:
            out.put(", uxtw")
            if mem.scaleShift > 0 {
                out.put(" #")
                out.putDecimal(UInt64(mem.scaleShift))
            }
        case .sxtw:
            out.put(", sxtw")
            if mem.scaleShift > 0 {
                out.put(" #")
                out.putDecimal(UInt64(mem.scaleShift))
            }
        case .lsl:
            if mem.scaleShift > 0 {
                out.put(", lsl #")
                out.putDecimal(UInt64(mem.scaleShift))
            }
        default:
            break
        }
        out.put(UInt8(ascii: "]"))
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

    @inline(__always)
    private static func isLogicalImmediate(_ m: Mnemonic) -> Bool {
        m == .and || m == .eor || m == .orr || m == .dupm
    }

    /// Unsigned-immediate text. AND/EOR/ORR/DUPM print the per-element value
    /// in hex. A DUPM→`mov` follows llvm's `printSVELogicalImm`: sign-extended
    /// from its element width as signed decimal when it fits int16, else the
    /// raw value as unsigned decimal when it fits uint16, else hex. Everything
    /// else prints plain unsigned decimal.
    @inline(__always)
    private static func putUnsignedImmediate(
        _ value: UInt64, width: UInt8, mnemonic: Mnemonic, into out: inout TextBytes,
    ) {
        if isLogicalImmediate(mnemonic) {
            out.put("#0x")
            out.putHex(value)
            return
        }
        if mnemonic == .mov {
            let signed = signExtend(value, width: UInt64(width))
            if signed >= -32768, signed <= 32767 {
                out.put(UInt8(ascii: "#"))
                out.putDecimal(signed)
                return
            }
            if value <= 0xFFFF {
                out.put(UInt8(ascii: "#"))
                out.putDecimal(value)
                return
            }
            out.put("#0x")
            out.putHex(value)
            return
        }
        out.put(UInt8(ascii: "#"))
        out.putDecimal(value)
    }

    @inline(__always)
    private static func signExtend(_ value: UInt64, width: UInt64) -> Int64 {
        if width >= 64 { return Int64(bitPattern: value) }
        let shift = UInt64(64) - width
        return Int64(bitPattern: value << shift) >> Int64(shift)
    }

    @inline(__always)
    private static func putShiftKind(_ k: ShiftKind, into out: inout TextBytes) {
        switch k {
        case .lsl: out.put("lsl")
        case .lsr: out.put("lsr")
        case .asr: out.put("asr")
        case .ror: out.put("ror")
        case .msl: out.put("msl")
        }
    }

    /// The element-size letter.
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

    /// The NEON arrangement suffix.
    @inline(__always)
    private static func putArrangement(_ a: VectorArrangement, into out: inout TextBytes) {
        switch a {
        case .b8: out.put("8b")
        case .b16: out.put("16b")
        case .h2: out.put("2h")
        case .h4: out.put("4h")
        case .h8: out.put("8h")
        case .s2: out.put("2s")
        case .s4: out.put("4s")
        case .d1: out.put("1d")
        case .d2: out.put("2d")
        case .q1: out.put("1q")
        }
    }

    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
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
        default: nil
        }
    }
}

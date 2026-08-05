// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer for the Branches, Exception, System tier.
// Renders an Instruction into llvm-mc-compatible disassembly text, matching
// the llvm-mc parity oracle across the full BES feature set. Per-mnemonic
// format dispatch covers every special case: bare-vs-immediate forms,
// hex-vs-decimal immediates, named barrier / PSTATE / sysreg / SYS aliases,
// BTI sub-target rendering, SP-vs-XZR contextual register text, etc.

/// Canonical llvm-mc-compatible disassembly text formatter for the
/// Branches, Exception, System family. The single source of truth for
/// how a BES `Instruction` becomes a one-line assembly string, consumed
/// by the `DisassemblyText` router behind `Instruction.text`.
enum BESCanonicalizer {
    /// Format `instruction` into canonical disassembly text. UNDEFINED
    /// contributes nothing (matching llvm-mc's `""` for invalid encodings).
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        putNamed(mnemonic: instruction.mnemonic, operands: instruction.operands, into: &out)
    }

    private static func putNamed(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        switch mnemonic {
        case .b, .bl:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            putLabelOperand(operands[0], into: &out)
        case .bCond, .bcCond:
            // operands[0] = .conditionCode(cond), operands[1] = .label
            guard operands.count >= 2,
                  case let .conditionCode(cond) = operands[0],
                  case let .label(off) = operands[1]
            else { return putUnknown(mnemonic, into: &out) }
            out.put(mnemonic == .bCond ? "b." : "bc.")
            putConditionName(cond, into: &out)
            out.put(" #")
            out.putDecimal(off)
        case .cbz, .cbnz:
            // [.register(Rt), .label(off)]
            guard operands.count >= 2 else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(operandRegister(operands[0]), into: &out)
            out.put(", ")
            putLabelOperand(operands[1], into: &out)
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne:
            putCompareBranch(mnemonic: mnemonic, operands: operands, into: &out)
        case .tbz, .tbnz:
            // [.register(Rt), .unsignedImmediate(bitPos), .label(off)]
            guard operands.count >= 3 else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(operandRegister(operands[0]), into: &out)
            out.put(", #")
            out.putDecimal(operandUnsignedImm(operands[1]))
            out.put(", ")
            putLabelOperand(operands[2], into: &out)
        case .svc, .hvc, .smc, .brk, .hlt:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            putHashHexOrZero(operandUnsignedImm(operands[0]), into: &out)
        case .udf:
            // UDF #imm16 — llvm-mc renders the immediate in decimal
            // (`udf #0`, `udf #43981`), unlike the hex SVC/BRK class.
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            out.put(UInt8(ascii: "#"))
            out.putDecimal(operandUnsignedImm(operands[0]))
        case .dcps1, .dcps2, .dcps3:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            let imm = operandUnsignedImm(operands[0])
            putMnemonic(mnemonic, into: &out)
            if imm != 0 {
                out.put(" #0x")
                out.putHex(imm)
            }
        case .br, .blr, .ret, .eret, .drps:
            putBranchReg(mnemonic: mnemonic, operands: operands, into: &out)
        case .braa, .brab, .blraa, .blrab,
             .braaz, .brabz, .blraaz, .blrabz:
            putAuthBranchSettable(mnemonic: mnemonic, operands: operands, into: &out)
        case .retaa, .retab, .eretaa, .eretab:
            putMnemonic(mnemonic, into: &out) // no operand
        case .nop, .yield, .wfe, .wfi, .sev, .sevl,
             .dgh, .csdb, .esb, .xpaclri,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .clrbhb, .gcsbDsync,
             .cfinv, .xaflag, .axflag,
             .ssbb, .pssbb, .sb:
            putMnemonic(mnemonic, into: &out)
        case .chkfeat:
            // llvm-mc renders CHKFEAT's implicit X16 operand: "chkfeat x16".
            out.put("chkfeat x16")
        case .psb, .tsb:
            // Both rendered as "psb csync" / "tsb csync" — no separate
            // operand, the `csync` literal is part of the syntax.
            putHead(mnemonic, into: &out)
            out.put("csync")
        case .bti:
            putBti(mnemonic: mnemonic, operands: operands, into: &out)
        case .hint:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            out.put(UInt8(ascii: "#"))
            out.putDecimal(operandUnsignedImm(operands[0]))
        case .clrex, .isb:
            putMnemonic(mnemonic, into: &out)
            if !operands.isEmpty {
                out.put(" #")
                out.putDecimal(operandUnsignedImm(operands[0]))
            }
        case .dsb, .dmb:
            putDsbOrDmb(mnemonic: mnemonic, operands: operands, into: &out)
        case .msr:
            // [.systemRegister(sysreg), .register(Rt)]
            guard operands.count >= 2,
                  case let .systemRegister(sysreg) = operands[0],
                  case let .register(rt) = operands[1]
            else { return out.put("?msr") }
            putHead(mnemonic, into: &out)
            putSystemRegisterName(sysreg, direction: .write, into: &out)
            out.put(", ")
            RegisterNames.put(rt, into: &out)
        case .mrs:
            // [.register(Rt), .systemRegister(sysreg)]
            guard operands.count >= 2,
                  case let .register(rt) = operands[0],
                  case let .systemRegister(sysreg) = operands[1]
            else { return out.put("?mrs") }
            putHead(mnemonic, into: &out)
            RegisterNames.put(rt, into: &out)
            out.put(", ")
            putSystemRegisterName(sysreg, direction: .read, into: &out)
        case .msrImm:
            // [.pstateField(field), .unsignedImmediate(imm4)]
            guard operands.count >= 2, case let .pstateField(field) = operands[0]
            else { return out.put("?msrImm") }
            putHead(mnemonic, into: &out)
            putPStateName(field, into: &out)
            out.put(", #")
            out.putDecimal(operandUnsignedImm(operands[1]))
        case .smstart, .smstop:
            // [.unsignedImmediate(target)] — 1 → sm, 2 → za, 3 → both (bare).
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putMnemonic(mnemonic, into: &out)
            switch operandUnsignedImm(operands[0]) {
            case 1: out.put(" sm")
            case 2: out.put(" za")
            default: break
            }
        case .sys:
            // [.systemOp(SystemOp(rawEncoding:))]
            guard !operands.isEmpty, case let .systemOp(op) = operands[0]
            else { return out.put("?sys") }
            putSys(mnemonic: mnemonic, rawEncoding: op.rawEncoding, into: &out)
        case .sysl:
            guard !operands.isEmpty, case let .systemOp(op) = operands[0]
            else { return out.put("?sysl") }
            putSysl(mnemonic: mnemonic, rawEncoding: op.rawEncoding, into: &out)
        case .sysp:
            guard !operands.isEmpty, case let .systemOp(op) = operands[0]
            else { return out.put("?sysp") }
            putSysp(rawEncoding: op.rawEncoding, into: &out)
        case .mrrs:
            // [.register(Xt), .register(Xt+1), .systemRegister(sysreg)]
            guard operands.count >= 3,
                  case let .register(rt1) = operands[0],
                  case let .register(rt2) = operands[1],
                  case let .systemRegister(sysreg) = operands[2]
            else { return out.put("?mrrs") }
            putHead(mnemonic, into: &out)
            RegisterNames.put(rt1, into: &out)
            out.put(", ")
            RegisterNames.put(rt2, into: &out)
            out.put(", ")
            putSystemRegisterName(sysreg, direction: .read, into: &out)
        case .msrr:
            // [.systemRegister(sysreg), .register(Xt), .register(Xt+1)]
            guard operands.count >= 3,
                  case let .systemRegister(sysreg) = operands[0],
                  case let .register(rt1) = operands[1],
                  case let .register(rt2) = operands[2]
            else { return out.put("?msrr") }
            putHead(mnemonic, into: &out)
            putSystemRegisterName(sysreg, direction: .write, into: &out)
            out.put(", ")
            RegisterNames.put(rt1, into: &out)
            out.put(", ")
            RegisterNames.put(rt2, into: &out)
        case .wfet, .wfit:
            // [.register(Rt)]
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(operandRegister(operands[0]), into: &out)
        default:
            out.put(UInt8(ascii: "?"))
            out.putDecimal(UInt64(mnemonic.rawValue))
        }
    }

    // MARK: per-mnemonic formatting helpers

    @inline(__always)
    private static func putHead(_ m: Mnemonic, into out: inout TextBytes) {
        putMnemonic(m, into: &out)
        out.put(UInt8(ascii: " "))
    }

    /// The `?<name>` sentinel a mis-shaped operand list renders as.
    @inline(__always)
    private static func putUnknown(_ m: Mnemonic, into out: inout TextBytes) {
        out.put(UInt8(ascii: "?"))
        putMnemonic(m, into: &out)
    }

    /// `#0` for zero, `#0x<hex>` otherwise — the SVC/BRK exception class.
    @inline(__always)
    private static func putHashHexOrZero(_ imm: UInt64, into out: inout TextBytes) {
        if imm == 0 {
            out.put("#0")
            return
        }
        out.put("#0x")
        out.putHex(imm)
    }

    private static func putBranchReg(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        if mnemonic == .eret || mnemonic == .drps {
            putMnemonic(mnemonic, into: &out)
            return
        }
        // RET with Rn=30 decodes with empty operands; other
        // RET forms and BR/BLR carry a single register operand.
        if operands.isEmpty {
            putMnemonic(mnemonic, into: &out)
            return
        }
        guard case let .register(rn) = operands[0] else { return putUnknown(mnemonic, into: &out) }
        putHead(mnemonic, into: &out)
        RegisterNames.put(rn, into: &out)
    }

    private static func putAuthBranchSettable(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        if mnemonic == .braa || mnemonic == .brab || mnemonic == .blraa || mnemonic == .blrab {
            guard operands.count >= 2,
                  case let .register(rn) = operands[0],
                  case let .register(rm) = operands[1]
            else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(rn, into: &out)
            out.put(", ")
            RegisterNames.put(rm, into: &out)
            return
        }
        guard !operands.isEmpty, case let .register(rn) = operands[0]
        else { return putUnknown(mnemonic, into: &out) }
        putHead(mnemonic, into: &out)
        RegisterNames.put(rn, into: &out)
    }

    private static func putBti(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        putMnemonic(mnemonic, into: &out)
        if operands.isEmpty { return }
        switch operandUnsignedImm(operands[0]) {
        case 0: break
        case 1: out.put(" c")
        case 2: out.put(" j")
        case 3: out.put(" jc")
        case let sub:
            out.put(" #")
            out.putDecimal(sub)
        }
    }

    private static func putCompareBranch(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        // Register/byte/halfword: [.register(Rt), .register(Rm), .label].
        // Immediate: [.register(Rt), .unsignedImmediate(imm6), .label].
        guard operands.count >= 3 else { return putUnknown(mnemonic, into: &out) }
        putHead(mnemonic, into: &out)
        RegisterNames.put(operandRegister(operands[0]), into: &out)
        out.put(", ")
        if case let .register(rm) = operands[1] {
            RegisterNames.put(rm, into: &out)
        } else {
            // Immediate form — imm6 rendered decimal.
            out.put(UInt8(ascii: "#"))
            out.putDecimal(operandUnsignedImm(operands[1]))
        }
        out.put(", ")
        putLabelOperand(operands[2], into: &out)
    }

    private static func putDsbOrDmb(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        putMnemonic(mnemonic, into: &out)
        if operands.isEmpty { return }
        out.put(UInt8(ascii: " "))
        switch operands[0] {
        case let .barrierOption(opt):
            putBarrierName(opt, into: &out)
        case let .unsignedImmediate(value, width):
            if width == 5 {
                // nXS form (CRm | 0x10 packed into width=5). Render as
                // the named nXS option.
                switch value & 0xF {
                case 2: out.put("oshnxs")
                case 6: out.put("nshnxs")
                case 10: out.put("ishnxs")
                case 14: out.put("synxs")
                default:
                    out.put(UInt8(ascii: "#"))
                    out.putDecimal(value)
                }
                return
            }
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        default:
            out.put(UInt8(ascii: "?"))
        }
    }

    // MARK: SYS / SYSL formatting

    /// `#<op1>, c<CRn>, c<CRm>, #<op2>` — the generic operand tail every
    /// SYS-class fallback shares.
    private static func putSysFields(
        op1: UInt8, CRn: UInt8, CRm: UInt8, op2: UInt8, into out: inout TextBytes,
    ) {
        out.put(UInt8(ascii: "#"))
        out.putDecimal(UInt64(op1))
        out.put(", c")
        out.putDecimal(UInt64(CRn))
        out.put(", c")
        out.putDecimal(UInt64(CRm))
        out.put(", #")
        out.putDecimal(UInt64(op2))
    }

    private static func putSys(
        mnemonic: Mnemonic, rawEncoding: UInt32, into out: inout TextBytes,
    ) {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        if let alias = BESSysAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            switch alias.kind {
            case .reg:
                out.putString(alias.name)
                out.put(", ")
                RegisterNames.put(RegisterRef.x(Rt), into: &out)
                return
            case .bareReg:
                out.putString(alias.name)
                out.put(UInt8(ascii: " "))
                RegisterNames.put(RegisterRef.x(Rt), into: &out)
                return
            case .noreg, .optReg:
                // .noreg renders bare only when Rt == 31; otherwise the
                // generic SYS form. .optReg never appears in the SYS table
                // (it is SYSL-only) — bare-at-31 is its rendering too.
                if Rt == 31 {
                    out.putString(alias.name)
                    return
                }
            }
        }
        // Generic SYS fallback.
        putHead(mnemonic, into: &out)
        putSysFields(op1: op1, CRn: CRn, CRm: CRm, op2: op2, into: &out)
        if Rt != 31 {
            out.put(", ")
            RegisterNames.put(RegisterRef.x(Rt), into: &out)
        }
    }

    private static func putSysl(
        mnemonic: Mnemonic, rawEncoding: UInt32, into out: inout TextBytes,
    ) {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        if let alias = BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            switch alias.kind {
            case .reg, .bareReg:
                out.putString(alias.name)
                out.put(UInt8(ascii: " "))
                RegisterNames.put(RegisterRef.x(Rt), into: &out)
            case .optReg, .noreg:
                // .optReg renders `name xN` at Rt != 31 and bare at 31;
                // .noreg never appears in the SYSL table (SYS-only).
                out.putString(alias.name)
                if Rt != 31 {
                    out.put(UInt8(ascii: " "))
                    RegisterNames.put(RegisterRef.x(Rt), into: &out)
                }
            }
            return
        }
        // Generic SYSL fallback — Rt is always rendered (incl. xzr).
        putHead(mnemonic, into: &out)
        RegisterNames.put(RegisterRef.x(Rt), into: &out)
        out.put(", ")
        putSysFields(op1: op1, CRn: CRn, CRm: CRm, op2: op2, into: &out)
    }

    private static func putSysp(rawEncoding: UInt32, into out: inout TextBytes) {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        // Rt and Rt+1 form a consecutive X-register pair; Rt == 31 → xzr pair.
        let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
        if let alias = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            // Aliased SYSP always renders the pair (incl. xzr, xzr).
            out.putString(alias.name)
            out.put(", ")
            putRegisterPair(Rt, rt2, into: &out)
            return
        }
        out.put("sysp ")
        putSysFields(op1: op1, CRn: CRn, CRm: CRm, op2: op2, into: &out)
        // Generic SYSP omits the pair when Rt == 31.
        if Rt != 31 {
            out.put(", ")
            putRegisterPair(Rt, rt2, into: &out)
        }
    }

    @inline(__always)
    private static func putRegisterPair(_ a: UInt8, _ b: UInt8, into out: inout TextBytes) {
        RegisterNames.put(RegisterRef.x(a), into: &out)
        out.put(", ")
        RegisterNames.put(RegisterRef.x(b), into: &out)
    }

    // MARK: shared helpers (immediate / register / labels)

    private static func putLabelOperand(_ op: Operand, into out: inout TextBytes) {
        guard case let .label(offset) = op else {
            out.put("?label")
            return
        }
        out.put(UInt8(ascii: "#"))
        out.putDecimal(offset)
    }

    @inline(__always)
    @_effects(readonly)
    private static func operandRegister(_ op: Operand) -> RegisterRef {
        guard case let .register(reg) = op else {
            return .xzr() // defensive; unit tests catch the mis-route
        }
        return reg
    }

    @inline(__always)
    @_effects(readonly)
    private static func operandUnsignedImm(_ op: Operand) -> UInt64 {
        switch op {
        case let .unsignedImmediate(value, _): value
        case let .immediate(value, _): UInt64(bitPattern: Int64(value))
        default: 0
        }
    }

    // MARK: name tables

    @inline(__always)
    private static func putConditionName(_ c: ConditionCode, into out: inout TextBytes) {
        switch c {
        case .eq: out.put("eq")
        case .ne: out.put("ne")
        case .cs: out.put("hs") // llvm-mc canonical
        case .cc: out.put("lo") // llvm-mc canonical
        case .mi: out.put("mi")
        case .pl: out.put("pl")
        case .vs: out.put("vs")
        case .vc: out.put("vc")
        case .hi: out.put("hi")
        case .ls: out.put("ls")
        case .ge: out.put("ge")
        case .lt: out.put("lt")
        case .gt: out.put("gt")
        case .le: out.put("le")
        case .al: out.put("al")
        case .nv: out.put("nv")
        }
    }

    @inline(__always)
    private static func putBarrierName(_ b: BarrierOption, into out: inout TextBytes) {
        switch b {
        case .oshld: out.put("oshld")
        case .oshst: out.put("oshst")
        case .osh: out.put("osh")
        case .nshld: out.put("nshld")
        case .nshst: out.put("nshst")
        case .nsh: out.put("nsh")
        case .ishld: out.put("ishld")
        case .ishst: out.put("ishst")
        case .ish: out.put("ish")
        case .ld: out.put("ld")
        case .st: out.put("st")
        case .sy: out.put("sy")
        }
    }

    private static func putPStateName(_ f: PSTATEField, into out: inout TextBytes) {
        // Lowercase to match the normalized oracle text.
        // llvm-mc emits uppercase canonical names ("SPSel", "DAIFSet")
        // but `normalizeDisassembly` lowercases for diff stability.
        switch f {
        case .spSel: out.put("spsel")
        case .daifSet: out.put("daifset")
        case .daifClr: out.put("daifclr")
        case .uao: out.put("uao")
        case .pan: out.put("pan")
        case .dit: out.put("dit")
        case .tco: out.put("tco")
        case .ssbs: out.put("ssbs")
        case .allInt: out.put("allint")
        case .pm: out.put("pm")
        case let .unknown(op1, op2):
            out.put("pstate")
            out.putDecimal(UInt64(op1))
            out.put(UInt8(ascii: "_"))
            out.putDecimal(UInt64(op2))
        }
    }

    /// Whether the access is MSR (write) or MRS (read) — drives the
    /// named-vs-S-form fallback for read-only / write-only registers.
    enum SystemRegisterDirection {
        case read // MRS
        case write // MSR
    }

    private static func putSystemRegisterName(
        _ s: SystemRegisterEncoding, direction: SystemRegisterDirection, into out: inout TextBytes,
    ) {
        if let named = SystemRegisterNameTable.lookup(s, direction: direction) {
            out.putString(named)
            return
        }
        // Generic s<op0>_<op1>_c<crn>_c<crm>_<op2> form — lowercase to
        // match the normalized oracle text (llvm-mc emits
        // uppercase, `normalizeDisassembly` lowercases for diff stability).
        out.put(UInt8(ascii: "s"))
        out.putDecimal(UInt64(s.op0))
        out.put(UInt8(ascii: "_"))
        out.putDecimal(UInt64(s.op1))
        out.put("_c")
        out.putDecimal(UInt64(s.crn))
        out.put("_c")
        out.putDecimal(UInt64(s.crm))
        out.put(UInt8(ascii: "_"))
        out.putDecimal(UInt64(s.op2))
    }
}

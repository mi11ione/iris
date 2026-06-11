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
    /// Format `instruction` to canonical disassembly text. Empty string means
    /// UNDEFINED (matches llvm-mc's `""` for invalid encodings).
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined { return "" }
        return formatNamed(mnemonic: instruction.mnemonic, operands: instruction.operands)
    }

    @_effects(readonly)
    private static func formatNamed(mnemonic: Mnemonic, operands: Instruction.Operands) -> String {
        switch mnemonic {
        case .b, .bl:
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) \(formatLabelOperand(operands[0]))"
        case .bCond:
            // operands[0] = .conditionCode(cond), operands[1] = .label
            guard operands.count >= 2,
                  case let .conditionCode(cond) = operands[0],
                  case let .label(off) = operands[1]
            else { return "?\(mnemonic.name)" }
            return "b.\(conditionName(cond)) #\(off)"
        case .bcCond:
            // BC.cond (FEAT_HBC) — same shape as b.cond with a "bc." prefix.
            guard operands.count >= 2,
                  case let .conditionCode(cond) = operands[0],
                  case let .label(off) = operands[1]
            else { return "?\(mnemonic.name)" }
            return "bc.\(conditionName(cond)) #\(off)"
        case .cbz, .cbnz:
            // [.register(Rt), .label(off)]
            guard operands.count >= 2 else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) \(operandRegister(operands[0]).name), \(formatLabelOperand(operands[1]))"
        case .cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
             .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
             .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne:
            return formatCompareBranch(mnemonic: mnemonic, operands: operands)
        case .tbz, .tbnz:
            // [.register(Rt), .unsignedImmediate(bitPos), .label(off)]
            guard operands.count >= 3 else { return "?\(mnemonic.name)" }
            let regText = operandRegister(operands[0]).name
            let bitText = formatDecimal(operandUnsignedImm(operands[1]))
            let lblText = formatLabelOperand(operands[2])
            return "\(mnemonic.name) \(regText), \(bitText), \(lblText)"
        case .svc, .hvc, .smc, .brk, .hlt:
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return formatExceptionWithImm(name: mnemonic.name, imm: operandUnsignedImm(operands[0]))
        case .udf:
            // UDF #imm16 — llvm-mc renders the immediate in decimal
            // (`udf #0`, `udf #43981`), unlike the hex SVC/BRK class.
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) #\(operandUnsignedImm(operands[0]))"
        case .dcps1, .dcps2, .dcps3:
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return formatDcpsWithImm(name: mnemonic.name, imm: operandUnsignedImm(operands[0]))
        case .br, .blr, .ret, .eret, .drps:
            return formatBranchReg(mnemonic: mnemonic, operands: operands)
        case .braa, .brab, .blraa, .blrab,
             .braaz, .brabz, .blraaz, .blrabz:
            return formatAuthBranchSettable(mnemonic: mnemonic, operands: operands)
        case .retaa, .retab, .eretaa, .eretab:
            return mnemonic.name // no operand
        case .nop, .yield, .wfe, .wfi, .sev, .sevl,
             .dgh, .csdb, .esb, .xpaclri,
             .paciaz, .paciasp, .pacibz, .pacibsp,
             .autiaz, .autiasp, .autibz, .autibsp,
             .pacia1716, .pacib1716, .autia1716, .autib1716,
             .clrbhb, .gcsbDsync,
             .cfinv, .xaflag, .axflag,
             .ssbb, .pssbb, .sb:
            return mnemonic.name
        case .chkfeat:
            // llvm-mc renders CHKFEAT's implicit X16 operand: "chkfeat x16".
            return "chkfeat x16"
        case .psb, .tsb:
            // Both rendered as "psb csync" / "tsb csync" — no separate
            // operand, the `csync` literal is part of the syntax.
            return "\(mnemonic.name) csync"
        case .bti:
            return formatBti(name: mnemonic.name, operands: operands)
        case .hint:
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) #\(operandUnsignedImm(operands[0]))"
        case .clrex:
            if operands.isEmpty { return mnemonic.name }
            return "\(mnemonic.name) #\(operandUnsignedImm(operands[0]))"
        case .isb:
            if operands.isEmpty { return mnemonic.name }
            return "\(mnemonic.name) #\(operandUnsignedImm(operands[0]))"
        case .dsb:
            return formatDsbOrDmb(name: mnemonic.name, operands: operands)
        case .dmb:
            return formatDsbOrDmb(name: mnemonic.name, operands: operands)
        case .msr:
            // [.systemRegister(sysreg), .register(Rt)]
            guard operands.count >= 2,
                  case let .systemRegister(sysreg) = operands[0],
                  case let .register(rt) = operands[1]
            else { return "?msr" }
            return "\(mnemonic.name) \(systemRegisterName(sysreg, direction: .write)), \(rt.name)"
        case .mrs:
            // [.register(Rt), .systemRegister(sysreg)]
            guard operands.count >= 2,
                  case let .register(rt) = operands[0],
                  case let .systemRegister(sysreg) = operands[1]
            else { return "?mrs" }
            return "\(mnemonic.name) \(rt.name), \(systemRegisterName(sysreg, direction: .read))"
        case .msrImm:
            // [.pstateField(field), .unsignedImmediate(imm4)]
            guard operands.count >= 2, case let .pstateField(field) = operands[0] else { return "?msrImm" }
            let imm = operandUnsignedImm(operands[1])
            return "\(mnemonic.name) \(pstateName(field)), #\(imm)"
        case .smstart, .smstop:
            // [.unsignedImmediate(target)] — 1 → sm, 2 → za, 3 → both (bare).
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            let target = operandUnsignedImm(operands[0])
            switch target {
            case 1: return "\(mnemonic.name) sm"
            case 2: return "\(mnemonic.name) za"
            default: return mnemonic.name
            }
        case .sys:
            // [.systemOp(SystemOp(rawEncoding:))]
            guard !operands.isEmpty, case let .systemOp(op) = operands[0] else { return "?sys" }
            return formatSys(name: mnemonic.name, rawEncoding: op.rawEncoding)
        case .sysl:
            guard !operands.isEmpty, case let .systemOp(op) = operands[0] else { return "?sysl" }
            return formatSysl(name: mnemonic.name, rawEncoding: op.rawEncoding)
        case .sysp:
            guard !operands.isEmpty, case let .systemOp(op) = operands[0] else { return "?sysp" }
            return formatSysp(rawEncoding: op.rawEncoding)
        case .mrrs:
            // [.register(Xt), .register(Xt+1), .systemRegister(sysreg)]
            guard operands.count >= 3,
                  case let .register(rt1) = operands[0],
                  case let .register(rt2) = operands[1],
                  case let .systemRegister(sysreg) = operands[2]
            else { return "?mrrs" }
            return "\(mnemonic.name) \(rt1.name), \(rt2.name), \(systemRegisterName(sysreg, direction: .read))"
        case .msrr:
            // [.systemRegister(sysreg), .register(Xt), .register(Xt+1)]
            guard operands.count >= 3,
                  case let .systemRegister(sysreg) = operands[0],
                  case let .register(rt1) = operands[1],
                  case let .register(rt2) = operands[2]
            else { return "?msrr" }
            return "\(mnemonic.name) \(systemRegisterName(sysreg, direction: .write)), \(rt1.name), \(rt2.name)"
        case .wfet, .wfit:
            // [.register(Rt)]
            guard !operands.isEmpty else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) \(operandRegister(operands[0]).name)"
        default:
            return "?\(mnemonic.rawValue)"
        }
    }

    // MARK: per-mnemonic formatting helpers

    @_effects(readonly)
    private static func formatExceptionWithImm(name: String, imm: UInt64) -> String {
        if imm == 0 {
            return "\(name) #0"
        }
        return "\(name) #\(formatHex(imm))"
    }

    @_effects(readonly)
    private static func formatDcpsWithImm(name: String, imm: UInt64) -> String {
        if imm == 0 {
            return name
        }
        return "\(name) #\(formatHex(imm))"
    }

    @_effects(readonly)
    private static func formatBranchReg(mnemonic: Mnemonic, operands: Instruction.Operands) -> String {
        if mnemonic == .eret || mnemonic == .drps {
            return mnemonic.name
        }
        // RET with Rn=30 decodes with empty operands; other
        // RET forms and BR/BLR carry a single register operand.
        if operands.isEmpty {
            return mnemonic.name
        }
        guard case let .register(rn) = operands[0] else { return "?\(mnemonic.name)" }
        return "\(mnemonic.name) \(rn.name)"
    }

    @_effects(readonly)
    private static func formatAuthBranchSettable(mnemonic: Mnemonic, operands: Instruction.Operands) -> String {
        if mnemonic == .braa || mnemonic == .brab || mnemonic == .blraa || mnemonic == .blrab {
            guard operands.count >= 2,
                  case let .register(rn) = operands[0],
                  case let .register(rm) = operands[1]
            else { return "?\(mnemonic.name)" }
            return "\(mnemonic.name) \(rn.name), \(rm.name)"
        }
        guard !operands.isEmpty,
              case let .register(rn) = operands[0]
        else { return "?\(mnemonic.name)" }
        return "\(mnemonic.name) \(rn.name)"
    }

    @_effects(readonly)
    private static func formatBti(name: String, operands: Instruction.Operands) -> String {
        if operands.isEmpty {
            return name
        }
        let sub = operandUnsignedImm(operands[0])
        switch sub {
        case 0: return name
        case 1: return "\(name) c"
        case 2: return "\(name) j"
        case 3: return "\(name) jc"
        default: return "\(name) #\(sub)"
        }
    }

    @_effects(readonly)
    private static func formatCompareBranch(mnemonic: Mnemonic, operands: Instruction.Operands) -> String {
        // Register/byte/halfword: [.register(Rt), .register(Rm), .label].
        // Immediate: [.register(Rt), .unsignedImmediate(imm6), .label].
        guard operands.count >= 3 else { return "?\(mnemonic.name)" }
        let rtText = operandRegister(operands[0]).name
        let lblText = formatLabelOperand(operands[2])
        if case let .register(rm) = operands[1] {
            return "\(mnemonic.name) \(rtText), \(rm.name), \(lblText)"
        }
        // Immediate form — imm6 rendered decimal.
        return "\(mnemonic.name) \(rtText), #\(operandUnsignedImm(operands[1])), \(lblText)"
    }

    @_effects(readonly)
    private static func formatDsbOrDmb(name: String, operands: Instruction.Operands) -> String {
        if operands.isEmpty {
            return name
        }
        switch operands[0] {
        case let .barrierOption(opt):
            return "\(name) \(barrierName(opt))"
        case let .unsignedImmediate(value, width):
            if width == 5 {
                // nXS form (CRm | 0x10 packed into width=5). Render as
                // the named nXS option.
                let crm = value & 0xF
                switch crm {
                case 2: return "\(name) oshnxs"
                case 6: return "\(name) nshnxs"
                case 10: return "\(name) ishnxs"
                case 14: return "\(name) synxs"
                default: return "\(name) #\(value)"
                }
            }
            return "\(name) #\(value)"
        default:
            return "\(name) ?"
        }
    }

    // MARK: SYS / SYSL formatting

    @_effects(readonly)
    private static func formatSys(name: String, rawEncoding: UInt32) -> String {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        if let alias = BESSysAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            switch alias.kind {
            case .reg:
                return "\(alias.name), \(RegisterRef.x(Rt).name)"
            case .bareReg:
                return "\(alias.name) \(RegisterRef.x(Rt).name)"
            case .noreg, .optReg:
                // .noreg renders bare only when Rt == 31; otherwise the
                // generic SYS form. .optReg never appears in the SYS table
                // (it is SYSL-only) — bare-at-31 is its rendering too.
                if Rt == 31 { return alias.name }
            }
        }
        // Generic SYS fallback.
        let rtPart = (Rt == 31) ? "" : ", \(RegisterRef.x(Rt).name)"
        return "\(name) #\(op1), c\(CRn), c\(CRm), #\(op2)\(rtPart)"
    }

    @_effects(readonly)
    private static func formatSysl(name: String, rawEncoding: UInt32) -> String {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        if let alias = BESSyslAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            switch alias.kind {
            case .reg, .bareReg:
                return "\(alias.name) \(RegisterRef.x(Rt).name)"
            case .optReg, .noreg:
                // .optReg renders `name xN` at Rt != 31 and bare at 31;
                // .noreg never appears in the SYSL table (SYS-only).
                return (Rt == 31) ? alias.name : "\(alias.name) \(RegisterRef.x(Rt).name)"
            }
        }
        // Generic SYSL fallback — Rt is always rendered (incl. xzr).
        return "\(name) \(RegisterRef.x(Rt).name), #\(op1), c\(CRn), c\(CRm), #\(op2)"
    }

    @_effects(readonly)
    private static func formatSysp(rawEncoding: UInt32) -> String {
        let op1 = UInt8((rawEncoding >> 16) & 0x7)
        let CRn = UInt8((rawEncoding >> 12) & 0xF)
        let CRm = UInt8((rawEncoding >> 8) & 0xF)
        let op2 = UInt8((rawEncoding >> 5) & 0x7)
        let Rt = UInt8(rawEncoding & 0x1F)
        // Rt and Rt+1 form a consecutive X-register pair; Rt == 31 → xzr pair.
        let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
        let pair = "\(RegisterRef.x(Rt).name), \(RegisterRef.x(rt2).name)"
        if let alias = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            // Aliased SYSP always renders the pair (incl. xzr, xzr).
            return "\(alias.name), \(pair)"
        }
        // Generic SYSP omits the pair when Rt == 31.
        if Rt == 31 {
            return "sysp #\(op1), c\(CRn), c\(CRm), #\(op2)"
        }
        return "sysp #\(op1), c\(CRn), c\(CRm), #\(op2), \(pair)"
    }

    // MARK: shared helpers (immediate / register / labels)

    @_effects(readonly)
    private static func formatLabelOperand(_ op: Operand) -> String {
        guard case let .label(offset) = op else { return "?label" }
        return "#\(offset)"
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

    @inline(__always)
    @_effects(readonly)
    private static func formatDecimal(_ value: UInt64) -> String {
        "#\(value)"
    }

    @inline(__always)
    @_effects(readonly)
    private static func formatHex(_ value: UInt64) -> String {
        "0x\(String(value, radix: 16))"
    }

    // MARK: name tables

    @_effects(readonly)
    private static func conditionName(_ c: ConditionCode) -> String {
        switch c {
        case .eq: "eq"
        case .ne: "ne"
        case .cs: "hs" // llvm-mc canonical
        case .cc: "lo" // llvm-mc canonical
        case .mi: "mi"
        case .pl: "pl"
        case .vs: "vs"
        case .vc: "vc"
        case .hi: "hi"
        case .ls: "ls"
        case .ge: "ge"
        case .lt: "lt"
        case .gt: "gt"
        case .le: "le"
        case .al: "al"
        case .nv: "nv"
        }
    }

    @_effects(readonly)
    private static func barrierName(_ b: BarrierOption) -> String {
        switch b {
        case .oshld: "oshld"
        case .oshst: "oshst"
        case .osh: "osh"
        case .nshld: "nshld"
        case .nshst: "nshst"
        case .nsh: "nsh"
        case .ishld: "ishld"
        case .ishst: "ishst"
        case .ish: "ish"
        case .ld: "ld"
        case .st: "st"
        case .sy: "sy"
        }
    }

    @_effects(readonly)
    private static func pstateName(_ f: PSTATEField) -> String {
        // Lowercase to match the normalized oracle text.
        // llvm-mc emits uppercase canonical names ("SPSel", "DAIFSet")
        // but `normalizeDisassembly` lowercases for diff stability.
        switch f {
        case .spSel: "spsel"
        case .daifSet: "daifset"
        case .daifClr: "daifclr"
        case .uao: "uao"
        case .pan: "pan"
        case .dit: "dit"
        case .tco: "tco"
        case .ssbs: "ssbs"
        case .allInt: "allint"
        case .pm: "pm"
        case let .unknown(op1, op2): "pstate\(op1)_\(op2)"
        }
    }

    /// Whether the access is MSR (write) or MRS (read) — drives the
    /// named-vs-S-form fallback for read-only / write-only registers.
    enum SystemRegisterDirection {
        case read // MRS
        case write // MSR
    }

    @_effects(readonly)
    private static func systemRegisterName(
        _ s: SystemRegisterEncoding, direction: SystemRegisterDirection,
    ) -> String {
        if let named = SystemRegisterNameTable.lookup(s, direction: direction) {
            return named
        }
        // Generic s<op0>_<op1>_c<crn>_c<crm>_<op2> form — lowercase to
        // match the normalized oracle text (llvm-mc emits
        // uppercase, `normalizeDisassembly` lowercases for diff stability).
        return "s\(s.op0)_\(s.op1)_c\(s.crn)_c\(s.crm)_\(s.op2)"
    }
}

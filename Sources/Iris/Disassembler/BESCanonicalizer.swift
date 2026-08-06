// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical llvm-mc-compatible text formatter for the Branches, Exception,
/// System family.
enum BESCanonicalizer {
    /// Format `instruction` into canonical disassembly text.
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
            guard operands.count >= 2,
                  case let .conditionCode(cond) = operands[0],
                  case let .label(off) = operands[1]
            else { return putUnknown(mnemonic, into: &out) }
            out.put(mnemonic == .bCond ? "b." : "bc.")
            putConditionName(cond, into: &out)
            out.put(" #")
            out.putDecimal(off)
        case .cbz, .cbnz:
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
        case .retaa, .retab, .eretaa, .eretab, .texit, .texitNb:
            putMnemonic(mnemonic, into: &out)
        case .retaasppcr, .retabsppcr:
            guard !operands.isEmpty, case let .register(rm) = operands[0]
            else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(rm, into: &out)
        case .retaasppc, .retabsppc:
            guard !operands.isEmpty, case let .immediate(offset, _) = operands[0]
            else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            out.put(UInt8(ascii: "#"))
            out.putDecimal(offset)
        case .tenter, .tenterNb:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            out.put(UInt8(ascii: "#"))
            out.putDecimal(operandUnsignedImm(operands[0]))
            if mnemonic == .tenterNb { out.put(", nb") }
        case .tchangef, .tchangefNb, .tchangeb, .tchangebNb:
            putTChange(mnemonic: mnemonic, operands: operands, into: &out)
        case .stshh:
            putStoreSharingHint(operands: operands, into: &out)
        case .shuh:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putMnemonic(mnemonic, into: &out)
            if operandUnsignedImm(operands[0]) == 1 { out.put(" ph") }
        case .pacm, .stcph, .dfb:
            putMnemonic(mnemonic, into: &out)
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
            out.put("chkfeat x16")
        case .psb, .tsb:
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
            guard operands.count >= 2,
                  case let .systemRegister(sysreg) = operands[0],
                  case let .register(rt) = operands[1]
            else { return out.put("?msr") }
            putHead(mnemonic, into: &out)
            putSystemRegisterName(sysreg, direction: .write, into: &out)
            out.put(", ")
            RegisterNames.put(rt, into: &out)
        case .mrs:
            guard operands.count >= 2,
                  case let .register(rt) = operands[0],
                  case let .systemRegister(sysreg) = operands[1]
            else { return out.put("?mrs") }
            putHead(mnemonic, into: &out)
            RegisterNames.put(rt, into: &out)
            out.put(", ")
            putSystemRegisterName(sysreg, direction: .read, into: &out)
        case .msrImm:
            guard operands.count >= 2, case let .pstateField(field) = operands[0]
            else { return out.put("?msrImm") }
            putHead(mnemonic, into: &out)
            putPStateName(field, into: &out)
            out.put(", #")
            out.putDecimal(operandUnsignedImm(operands[1]))
        case .smstart, .smstop:
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putMnemonic(mnemonic, into: &out)
            switch operandUnsignedImm(operands[0]) {
            case 1: out.put(" sm")
            case 2: out.put(" za")
            default: break
            }
        case .sys:
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
            guard !operands.isEmpty else { return putUnknown(mnemonic, into: &out) }
            putHead(mnemonic, into: &out)
            RegisterNames.put(operandRegister(operands[0]), into: &out)
        default:
            out.put(UInt8(ascii: "?"))
            out.putDecimal(UInt64(mnemonic.rawValue))
        }
    }

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

    /// `#0` for zero, `#0x<hex>` otherwise.
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
        case 0: out.put(" r")
        case 1: out.put(" c")
        case 2: out.put(" j")
        case 3: out.put(" jc")
        case let sub:
            out.put(" #")
            out.putDecimal(sub)
        }
    }

    private static func putTChange(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        guard operands.count >= 2, case let .register(rd) = operands[0]
        else { return putUnknown(mnemonic, into: &out) }
        putHead(mnemonic, into: &out)
        RegisterNames.put(rd, into: &out)
        out.put(", ")
        if case let .register(rn) = operands[1] {
            RegisterNames.put(rn, into: &out)
        } else {
            out.put(UInt8(ascii: "#"))
            out.putDecimal(operandUnsignedImm(operands[1]))
        }
        if mnemonic == .tchangefNb || mnemonic == .tchangebNb { out.put(", nb") }
    }

    private static func putStoreSharingHint(
        operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        putMnemonic(.stshh, into: &out)
        guard !operands.isEmpty else { return }
        switch operandUnsignedImm(operands[0]) {
        case 0: out.put(" keep")
        case 1: out.put(" strm")
        case let sub:
            out.put(" #")
            out.putDecimal(sub)
        }
    }

    private static func putCompareBranch(
        mnemonic: Mnemonic, operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        guard operands.count >= 3 else { return putUnknown(mnemonic, into: &out) }
        putHead(mnemonic, into: &out)
        RegisterNames.put(operandRegister(operands[0]), into: &out)
        out.put(", ")
        if case let .register(rm) = operands[1] {
            RegisterNames.put(rm, into: &out)
        } else {
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

    /// `#<op1>, c<CRn>, c<CRm>, #<op2>`.
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
            case .optCommaReg:
                out.putString(alias.name)
                if Rt != 31 {
                    out.put(", ")
                    RegisterNames.put(RegisterRef.x(Rt), into: &out)
                }
                return
            case .noreg, .optReg, .regThenName:
                if Rt == 31 {
                    out.putString(alias.name)
                    return
                }
            }
        }
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
            case let .regThenName(operation):
                out.putString(alias.name)
                out.put(UInt8(ascii: " "))
                RegisterNames.put(RegisterRef.x(Rt), into: &out)
                out.put(", ")
                out.putString(operation)
            case .optReg, .noreg, .optCommaReg:
                out.putString(alias.name)
                if Rt != 31 {
                    out.put(UInt8(ascii: " "))
                    RegisterNames.put(RegisterRef.x(Rt), into: &out)
                }
            }
            return
        }
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
        let rt2: UInt8 = (Rt == 31) ? 31 : (Rt &+ 1)
        if let alias = BESSyspAliasTable.lookup(op1: op1, CRn: CRn, CRm: CRm, op2: op2) {
            out.putString(alias.name)
            out.put(", ")
            putRegisterPair(Rt, rt2, into: &out)
            return
        }
        out.put("sysp ")
        putSysFields(op1: op1, CRn: CRn, CRm: CRm, op2: op2, into: &out)
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
            return .xzr()
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
    private static func putConditionName(_ c: ConditionCode, into out: inout TextBytes) {
        switch c {
        case .eq: out.put("eq")
        case .ne: out.put("ne")
        case .cs: out.put("hs")
        case .cc: out.put("lo")
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

    /// Whether the access is MSR (write) or MRS (read).
    enum SystemRegisterDirection {
        case read
        case write
    }

    private static func putSystemRegisterName(
        _ s: SystemRegisterEncoding, direction: SystemRegisterDirection, into out: inout TextBytes,
    ) {
        if let named = SystemRegisterNameTable.lookup(s, direction: direction) {
            out.putString(named)
            return
        }
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

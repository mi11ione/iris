// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical llvm-mc-compatible disassembly text formatter for the Data
/// Processing.
enum DPRCanonicalizer {
    /// The byte path.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
            return
        }
        putMnemonic(instruction.mnemonic, into: &out)
        let operands = instruction.operands
        if operands.isEmpty { return }
        out.put(UInt8(ascii: " "))
        for idx in 0 ..< operands.count {
            if idx > 0 { out.put(", ") }
            let op = operands[idx]
            if case let .extendedRegister(reg, extend, shift) = op,
               extendedRegisterCollapses(reg: reg, extend: extend, operands: operands, idx: idx)
            {
                RegisterNames.put(reg, into: &out)
                if shift != 0 {
                    out.put(", lsl #")
                    out.putDecimal(UInt64(shift))
                }
            } else {
                putOperand(op, into: &out)
            }
        }
    }

    /// Whether an `.extendedRegister` operand falls in the SP-extended
    /// display-collapse case.
    @_effects(readonly)
    private static func extendedRegisterCollapses(
        reg: RegisterRef, extend: ExtendKind, operands: Instruction.Operands, idx: Int,
    ) -> Bool {
        let naturalExtend: ExtendKind = reg.width == .x64 ? .uxtx : .uxtw
        guard extend == naturalExtend else { return false }
        for j in 0 ..< idx {
            guard case let .register(r) = operands[j] else { continue }
            if r.role == .stackPointer, r.width == reg.width {
                return true
            }
        }
        return false
    }

    private static func putOperand(_ operand: Operand, into out: inout TextBytes) {
        switch operand {
        case let .register(reg):
            RegisterNames.put(reg, into: &out)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .shiftedRegister(reg, kind, amount):
            RegisterNames.put(reg, into: &out)
            out.put(", ")
            putShiftKind(kind, into: &out)
            out.put(" #")
            out.putDecimal(UInt64(amount))
        case let .extendedRegister(reg, extend, shift):
            RegisterNames.put(reg, into: &out)
            out.put(", ")
            putExtendKind(extend, into: &out)
            if shift != 0 {
                out.put(" #")
                out.putDecimal(UInt64(shift))
            }
        case let .conditionCode(c):
            putConditionName(c, into: &out)
        case .vectorRegister, .floatImmediate, .label, .memory,
             .systemRegister, .pstateField, .barrierOption,
             .prefetchOperation, .systemOp, .amxField, .amxUnknown,
             .shiftAmount, .pageLabel,
             .scalableVector, .scalablePredicate, .scalableVectorGroup,
             .predicateGroup, .zaTile, .zaTileSlice, .zaArrayVector,
             .zt0, .scalableMemory, .svePredicatePattern,
             .vectorLengthMultiplier:
            out.put("?unsupported-operand")
        }
    }

    @inline(__always)
    private static func putShiftKind(_ s: ShiftKind, into out: inout TextBytes) {
        switch s {
        case .lsl: out.put("lsl")
        case .lsr: out.put("lsr")
        case .asr: out.put("asr")
        case .ror: out.put("ror")
        case .msl: out.put("msl")
        }
    }

    @inline(__always)
    private static func putExtendKind(_ e: ExtendKind, into out: inout TextBytes) {
        switch e {
        case .none: break
        case .uxtb: out.put("uxtb")
        case .uxth: out.put("uxth")
        case .uxtw: out.put("uxtw")
        case .uxtx: out.put("uxtx")
        case .sxtb: out.put("sxtb")
        case .sxth: out.put("sxth")
        case .sxtw: out.put("sxtw")
        case .sxtx: out.put("sxtx")
        case .lsl: out.put("lsl")
        }
    }

    /// Lowercase llvm-mc condition name.
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
}

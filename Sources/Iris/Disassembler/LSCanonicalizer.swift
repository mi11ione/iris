// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer for the Loads & Stores family. Mirrors
// the DPRCanonicalizer / BESCanonicalizer / DPICanonicalizer pattern:
// per-mnemonic formatting, lowercase output, single space between
// mnemonic and operand list, comma-space between operands.
//
// Special memory-operand rendering rules:
//   [Rn]                                — no offset, no index, no writeback
//   [Rn, #imm]                          — immediate offset, displacement != 0
//   [Rn, Wm, uxtw {#amount}]            — register offset with extend
//   [Rn, Xm{, lsl #amount}]             — register offset, LSL/UXTX collapses
//   [Rn], #imm                          — post-index writeback
//   [Rn, #imm]!                         — pre-index writeback
//   #imm                                — PC-relative literal (no brackets)

enum LSCanonicalizer {
    @_effects(readonly)
    @_optimize(speed)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined { return "" }
        // MTE L/S flows through LoadsAndStoresDecoder's case 0b011001
        // delegation; route crypto-range mnemonics to their canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            return CryptoAppleExtensionsCanonicalizer.format(instruction)
        }
        let mn = instruction.mnemonic.name
        // FEAT_MOPS CPY/SET carry a `[Xd]!, …` / `…, Xn!` syntax with
        // trailing `!` on registers/brackets that the generic operand
        // formatter cannot express; render it directly.
        let r = instruction.mnemonic.rawValue
        if (2330 ... 2449).contains(r) {
            return "\(mn) \(formatMOPSOperands(instruction))"
        }
        // FEAT_RPRES RPRFM's first operand is a 6-bit range-prefetch op with
        // a small symbolic-name set (others rendered `#N`).
        if instruction.mnemonic == .rprfm {
            return "\(mn) \(formatRPRFMOperands(instruction.operands))"
        }
        let ops = formatOperands(instruction.operands)
        return ops.isEmpty ? mn : "\(mn) \(ops)"
    }

    /// Render MOPS operands. CPY/CPYF (rawValue 2330..2425) →
    /// `[Xd]!, [Xs]!, Xn!`; SET/SETG (2426..2449) → `[Xd]!, Xn!, Xs`.
    @_effects(readonly)
    private static func formatMOPSOperands(_ instruction: Instruction) -> String {
        let ops = instruction.operands
        guard ops.count == 3,
              case let .register(r0) = ops[0],
              case let .register(r1) = ops[1],
              case let .register(r2) = ops[2]
        else { return "" }
        let a = r0.name
        let b = r1.name
        let c = r2.name
        if instruction.mnemonic.rawValue <= 2425 {
            // CPY/CPYF: dest and source are address registers (bracketed),
            // count register carries a trailing `!`.
            return "[\(a)]!, [\(b)]!, \(c)!"
        }
        // SET/SETG: dest address bracketed, count register `!`, data register bare.
        return "[\(a)]!, \(b)!, \(c)"
    }

    /// Render RPRFM operands: `<prfop>, Xm, [Xn]`. The 6-bit prfop has
    /// symbolic names only for {0,1,4,5}; all others render as `#N`.
    @_effects(readonly)
    private static func formatRPRFMOperands(_ ops: Instruction.Operands) -> String {
        guard ops.count == 3,
              case let .immediate(prfop, _) = ops[0]
        else { return formatOperands(ops) }
        let opText = switch prfop {
        case 0: "pldkeep"
        case 1: "pstkeep"
        case 4: "pldstrm"
        case 5: "pststrm"
        default: "#\(prfop)"
        }
        return "\(opText), \(formatOperand(ops[1])), \(formatOperand(ops[2]))"
    }

    @_effects(readonly)
    private static func formatOperands(_ operands: Instruction.Operands) -> String {
        if operands.isEmpty { return "" }
        var result = ""
        result.reserveCapacity(operands.count * 12)
        result.append(formatOperand(operands[0]))
        for i in 1 ..< operands.count {
            result.append(", ")
            result.append(formatOperand(operands[i]))
        }
        return result
    }

    @_effects(readonly)
    private static func formatOperand(_ operand: Operand) -> String {
        switch operand {
        case let .register(reg):
            reg.name
        case let .immediate(value, _):
            "#\(value)"
        case let .unsignedImmediate(value, _):
            "#\(value)"
        case let .memory(mem):
            formatMemoryOperand(mem)
        case let .prefetchOperation(p):
            prefetchText(p)
        // L/S decoders never emit these cases; the arm exists so the
        // `Operand` switch stays exhaustive without trapping.
        case .vectorRegister, .floatImmediate, .label, .shiftedRegister,
             .extendedRegister, .systemRegister, .conditionCode,
             .pstateField, .barrierOption, .systemOp, .amxField,
             .amxUnknown, .shiftAmount, .pageLabel:
            "?unsupported-operand"
        }
    }

    /// Format a ``MemoryOperand`` per the llvm-mc disassembly convention.
    /// PC-base literal loads render as `#<displacement>` (no brackets).
    @_effects(readonly)
    private static func formatMemoryOperand(_ mem: MemoryOperand) -> String {
        let baseText: String
        switch mem.base {
        case .pc:
            return "#\(mem.displacement)"
        case let .register(baseReg):
            baseText = baseReg.name
        }

        // `mem.shift == 0xFF` is the "no #amount displayed" sentinel set
        // by LoadStoreRegisterOffsetDecode for UXTW/SXTW/SXTX with S=0.
        // `.none` extend means LSL/UXTX collapse to bare `[Rn, Xm]`,
        // matching llvm-mc; other extends keep their keyword.
        if let index = mem.index {
            let indexText = index.name
            let extendText = extendKindName(mem.extend)
            let needsExtendKeyword = mem.extend != .none
            let suffix = if !needsExtendKeyword {
                ""
            } else if mem.shift == 0xFF {
                ", \(extendText)"
            } else {
                ", \(extendText) #\(mem.shift)"
            }
            return "[\(baseText), \(indexText)\(suffix)]"
        }

        switch mem.writeback {
        case .none:
            // Drop `#0` for every `.none` writeback memory
            // operand — pair forms included. llvm-mc disassembles
            // `ldp x0, x1, [x2, #0]` as `ldp x0, x1, [x2]`.
            if mem.displacement == 0 {
                return "[\(baseText)]"
            }
            return "[\(baseText), #\(mem.displacement)]"
        case .preIndex:
            return "[\(baseText), #\(mem.displacement)]!"
        case .postIndex:
            return "[\(baseText)], #\(mem.displacement)"
        }
    }

    /// Render a ``PrefetchOperation`` as its symbolic mnemonic
    /// (pldl1keep .. pstl3strm) or `#<N>` for reserved encodings.
    @_effects(readonly)
    private static func prefetchText(_ p: PrefetchOperation) -> String {
        let typeName: String
        switch p.operation {
        case .loadData: typeName = "pld"
        case .loadInstruction: typeName = "pli"
        case .storeData: typeName = "pst"
        case .reserved: return "#\(p.rawValue)"
        }
        let levelName = switch p.target {
        case .l1: "l1"
        case .l2: "l2"
        case .l3: "l3"
        case .slc: "slc"
        }
        let policyName: String = p.policy == .keep ? "keep" : "strm"
        return "\(typeName)\(levelName)\(policyName)"
    }

    @inline(__always)
    @_effects(readonly)
    private static func extendKindName(_ e: ExtendKind) -> String {
        switch e {
        case .none: ""
        case .uxtb: "uxtb"
        case .uxth: "uxth"
        case .uxtw: "uxtw"
        case .uxtx: "uxtx"
        case .sxtb: "sxtb"
        case .sxth: "sxth"
        case .sxtw: "sxtw"
        case .sxtx: "sxtx"
        case .lsl: "lsl"
        }
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

enum LSCanonicalizer {
    /// The byte path.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
            return
        }
        putMnemonic(instruction.mnemonic, into: &out)
        let r = instruction.mnemonic.rawValue
        if (2330 ... 2449).contains(r) {
            out.put(UInt8(ascii: " "))
            putMOPSOperands(instruction, into: &out)
            return
        }
        if (2540 ... 2551).contains(r) {
            out.put(UInt8(ascii: " "))
            putSETGOOperands(instruction.operands, into: &out)
            return
        }
        if instruction.mnemonic == .rprfm {
            out.put(UInt8(ascii: " "))
            putRPRFMOperands(instruction.operands, into: &out)
            return
        }
        let operands = instruction.operands
        if operands.isEmpty { return }
        out.put(UInt8(ascii: " "))
        putOperand(operands[0], into: &out)
        for i in 1 ..< operands.count {
            out.put(", ")
            putOperand(operands[i], into: &out)
        }
    }

    /// Render MOPS operands.
    private static func putMOPSOperands(_ instruction: Instruction, into out: inout TextBytes) {
        let ops = instruction.operands
        guard ops.count == 3,
              case let .register(r0) = ops[0],
              case let .register(r1) = ops[1],
              case let .register(r2) = ops[2]
        else { return }
        if instruction.mnemonic.rawValue <= 2425 {
            out.put(UInt8(ascii: "["))
            RegisterNames.put(r0, into: &out)
            out.put("]!, [")
            RegisterNames.put(r1, into: &out)
            out.put("]!, ")
            RegisterNames.put(r2, into: &out)
            out.put(UInt8(ascii: "!"))
            return
        }
        out.put(UInt8(ascii: "["))
        RegisterNames.put(r0, into: &out)
        out.put("]!, ")
        RegisterNames.put(r1, into: &out)
        out.put("!, ")
        RegisterNames.put(r2, into: &out)
    }

    /// Render SETGO operands: `[Xd]!, Xn!`.
    private static func putSETGOOperands(_ ops: Instruction.Operands, into out: inout TextBytes) {
        guard ops.count == 2,
              case let .register(r0) = ops[0],
              case let .register(r1) = ops[1]
        else { return }
        out.put(UInt8(ascii: "["))
        RegisterNames.put(r0, into: &out)
        out.put("]!, ")
        RegisterNames.put(r1, into: &out)
        out.put(UInt8(ascii: "!"))
    }

    /// Render RPRFM operands.
    private static func putRPRFMOperands(
        _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        guard ops.count == 3,
              case let .immediate(prfop, _) = ops[0]
        else {
            var first = true
            for op in ops {
                if !first { out.put(", ") }
                first = false
                putOperand(op, into: &out)
            }
            return
        }
        switch prfop {
        case 0: out.put("pldkeep")
        case 1: out.put("pstkeep")
        case 4: out.put("pldstrm")
        case 5: out.put("pststrm")
        default:
            out.put(UInt8(ascii: "#"))
            out.putDecimal(prfop)
        }
        out.put(", ")
        putOperand(ops[1], into: &out)
        out.put(", ")
        putOperand(ops[2], into: &out)
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
        case let .memory(mem):
            putMemoryOperand(mem, into: &out)
        case let .prefetchOperation(p):
            putPrefetch(p, into: &out)
        case .vectorRegister, .floatImmediate, .label, .shiftedRegister,
             .extendedRegister, .systemRegister, .conditionCode,
             .pstateField, .barrierOption, .systemOp, .amxField,
             .amxUnknown, .shiftAmount, .pageLabel,
             .scalableVector, .scalablePredicate, .scalableVectorGroup,
             .predicateGroup, .zaTile, .zaTileSlice, .zaArrayVector,
             .zt0, .scalableMemory, .svePredicatePattern,
             .vectorLengthMultiplier:
            out.put("?unsupported-operand")
        }
    }

    /// Format a ``MemoryOperand`` per the llvm-mc disassembly convention.
    private static func putMemoryOperand(_ mem: MemoryOperand, into out: inout TextBytes) {
        let baseReg: RegisterRef
        switch mem.base {
        case .pc:
            out.put(UInt8(ascii: "#"))
            out.putDecimal(mem.displacement)
            return
        case let .register(reg):
            baseReg = reg
        }

        if let index = mem.index {
            out.put(UInt8(ascii: "["))
            RegisterNames.put(baseReg, into: &out)
            out.put(", ")
            RegisterNames.put(index, into: &out)
            putExtendSuffix(mem, into: &out)
            out.put(UInt8(ascii: "]"))
            return
        }

        switch mem.writeback {
        case .none:
            out.put(UInt8(ascii: "["))
            RegisterNames.put(baseReg, into: &out)
            if mem.displacement != 0 {
                out.put(", #")
                out.putDecimal(mem.displacement)
            }
            out.put(UInt8(ascii: "]"))
        case .preIndex:
            out.put(UInt8(ascii: "["))
            RegisterNames.put(baseReg, into: &out)
            out.put(", #")
            out.putDecimal(mem.displacement)
            out.put("]!")
        case .postIndex:
            out.put(UInt8(ascii: "["))
            RegisterNames.put(baseReg, into: &out)
            out.put("], #")
            out.putDecimal(mem.displacement)
        }
    }

    /// Render a ``PrefetchOperation`` as its symbolic mnemonic (pldl1keep ..
    private static func putPrefetch(_ p: PrefetchOperation, into out: inout TextBytes) {
        switch p.operation {
        case .loadData: out.put("pld")
        case .loadInstruction: out.put("pli")
        case .storeData: out.put("pst")
        case .reserved:
            out.put(UInt8(ascii: "#"))
            out.putDecimal(UInt64(p.rawValue))
            return
        }
        switch p.target {
        case .l1: out.put("l1")
        case .l2: out.put("l2")
        case .l3: out.put("l3")
        case .slc: out.put("slc")
        }
        if p.policy == .keep { out.put("keep") } else { out.put("strm") }
    }

    /// The `, <extend>{ #<amount>}` tail of a register-offset memory operand.
    @inline(__always)
    private static func putExtendSuffix(_ mem: MemoryOperand, into out: inout TextBytes) {
        switch mem.extend {
        case .none: return
        case .uxtb: out.put(", uxtb")
        case .uxth: out.put(", uxth")
        case .uxtw: out.put(", uxtw")
        case .uxtx: out.put(", uxtx")
        case .sxtb: out.put(", sxtb")
        case .sxth: out.put(", sxth")
        case .sxtw: out.put(", sxtw")
        case .sxtx: out.put(", sxtx")
        case .lsl: out.put(", lsl")
        }
        if mem.shift != 0xFF {
            out.put(" #")
            out.putDecimal(UInt64(mem.shift))
        }
    }
}

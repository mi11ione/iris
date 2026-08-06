// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonicalizer for crypto/Apple-extensions records (crypto extensions, PAC
/// standalone, MTE, AMX).
enum CryptoAppleExtensionsCanonicalizer {
    /// Whether the mnemonic is in this family's reserved range.
    @inlinable
    static func owns(_ mnemonic: Mnemonic) -> Bool {
        mnemonic.rawValue >= 12288 && mnemonic.rawValue <= 16383
    }

    /// The byte path.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        guard owns(instruction.mnemonic) else {
            out.put(UInt8(ascii: "?"))
            out.putDecimal(UInt64(instruction.mnemonic.rawValue))
            return
        }
        if instruction.mnemonic == .amxUnknownOp {
            putOperands(instruction, into: &out)
            return
        }
        putMnemonic(instruction.mnemonic, into: &out)
        let mark = out.count
        out.put(UInt8(ascii: " "))
        putOperands(instruction, into: &out)
        if out.count == mark &+ 1 { out.count = mark }
    }

    private static func putOperands(_ instruction: Instruction, into out: inout TextBytes) {
        switch instruction.mnemonic {
        case .irg:
            putIRG(instruction.operands, into: &out)
        case .stg, .stzg, .st2g, .stz2g:
            putMTEStore(instruction.operands, into: &out)
        case .amxSet, .amxClr:
            break
        case .amxUnknownOp:
            if case let .amxUnknown(rawFields) = instruction.operands.first {
                putLongHex(rawFields, into: &out)
            } else {
                putLongHex(instruction.encoding, into: &out)
            }
        case .amxLdx, .amxLdy, .amxStx, .amxSty, .amxLdz, .amxStz,
             .amxLdzi, .amxStzi, .amxExtrx, .amxExtry,
             .amxFma64, .amxFms64, .amxFma32, .amxFms32, .amxMac16,
             .amxFma16, .amxFms16, .amxVecint, .amxVecfp, .amxMatint,
             .amxMatfp, .amxGenlut:
            if case let .amxField(f) = instruction.operands.first {
                putXRegisterName(f.operandField, into: &out)
            }
        default:
            putDefaultOperandList(instruction.operands, into: &out)
        }
    }

    private static func putDefaultOperandList(
        _ operands: Instruction.Operands, into out: inout TextBytes,
    ) {
        for i in 0 ..< operands.count {
            if i > 0 { out.put(", ") }
            putGenericOperand(operands[i], into: &out)
        }
    }

    private static func putGenericOperand(_ operand: Operand, into out: inout TextBytes) {
        switch operand {
        case let .register(reg):
            RegisterNames.put(reg, into: &out)
        case let .vectorRegister(vr):
            putVectorRegister(vr, into: &out)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .memory(mem):
            putMemoryOperand(mem, into: &out)
        case let .amxField(field):
            putXRegisterName(field.operandField, into: &out)
        case let .amxUnknown(rawFields):
            putLongHex(rawFields, into: &out)
        case .floatImmediate, .label, .shiftedRegister, .extendedRegister,
             .systemRegister, .conditionCode, .pstateField, .barrierOption,
             .prefetchOperation, .systemOp, .shiftAmount, .pageLabel,
             .scalableVector, .scalablePredicate, .scalableVectorGroup,
             .predicateGroup, .zaTile, .zaTileSlice, .zaArrayVector,
             .zt0, .scalableMemory, .svePredicatePattern,
             .vectorLengthMultiplier:
            out.put("?unsupported-operand")
        }
    }

    /// IRG operand rendering.
    private static func putIRG(_ operands: Instruction.Operands, into out: inout TextBytes) {
        guard operands.count == 3 else {
            putDefaultOperandList(operands, into: &out)
            return
        }
        if case let .register(rm) = operands[2], rm.isZeroRegister {
            putGenericOperand(operands[0], into: &out)
            out.put(", ")
            putGenericOperand(operands[1], into: &out)
            return
        }
        putDefaultOperandList(operands, into: &out)
    }

    /// STG / STZG / ST2G / STZ2G rendering.
    private static func putMTEStore(_ operands: Instruction.Operands, into out: inout TextBytes) {
        guard operands.count == 2,
              case let .memory(mem) = operands[1]
        else {
            putDefaultOperandList(operands, into: &out)
            return
        }
        putGenericOperand(operands[0], into: &out)
        out.put(", ")
        putMemoryOperand(mem, into: &out)
    }

    /// Format a MemoryOperand.
    private static func putMemoryOperand(_ mem: MemoryOperand, into out: inout TextBytes) {
        out.put(UInt8(ascii: "["))
        switch mem.base {
        case let .register(reg): RegisterNames.put(reg, into: &out)
        case .pc: out.put("pc")
        }
        let imm = mem.displacement
        switch mem.writeback {
        case .none:
            if imm != 0 {
                out.put(", #")
                out.putDecimal(imm)
            }
            out.put(UInt8(ascii: "]"))
        case .preIndex:
            out.put(", #")
            out.putDecimal(imm)
            out.put("]!")
        case .postIndex:
            out.put("], #")
            out.putDecimal(imm)
        }
    }

    private static func putVectorRegister(_ vr: VectorRegisterRef, into out: inout TextBytes) {
        let n = UInt64(vr.registerIndex)
        switch vr.view {
        case let .full(arrangement):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            putArrangementName(arrangement, into: &out)
        case let .scalar(size):
            putScalarPrefix(size, into: &out)
            out.putDecimal(n)
        case let .element(arrangement, index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            putScalarSizeName(arrangement.elementSize, into: &out)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        case let .elementGroup(elementSize, count, index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "."))
            out.putDecimal(UInt64(count))
            putScalarSizeName(elementSize, into: &out)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        case let .lane(index):
            out.put(UInt8(ascii: "v"))
            out.putDecimal(n)
            out.put(UInt8(ascii: "["))
            out.putDecimal(UInt64(index))
            out.put(UInt8(ascii: "]"))
        }
    }

    @inline(__always)
    private static func putArrangementName(_ a: VectorArrangement, into out: inout TextBytes) {
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

    @inline(__always)
    private static func putScalarPrefix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        case .d: out.put("d")
        case .q: out.put("q")
        }
    }

    @inline(__always)
    private static func putScalarSizeName(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        default: out.put("d")
        }
    }

    /// Render an AMX 5-bit operand subfield as an X register (X0…X30, XZR).
    @inline(__always)
    private static func putXRegisterName(_ field: UInt8, into out: inout TextBytes) {
        let n = field & 0x1F
        if n == 31 {
            out.put("xzr")
            return
        }
        out.put(UInt8(ascii: "x"))
        out.putDecimal(UInt64(n))
    }

    /// Render a 32-bit encoding as `.long 0xXXXXXXXX` matching llvm-mc's
    /// fallback for unknown words.
    @inline(__always)
    private static func putLongHex(_ value: UInt32, into out: inout TextBytes) {
        out.put(".long 0x")
        out.putHex(UInt64(value))
    }
}

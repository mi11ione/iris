// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Crypto/Apple-extensions canonicalizer: formats Instructions produced
// by the crypto / PAC / MTE / AMX decoders into llvm-mc-compatible
// disassembly text. Mirrors the per-family canonicalizer pattern of the
// other families: lowercase output, single space after the mnemonic,
// comma-space between operands. Records whose mnemonic falls outside
// the family's mnemonic range [12288, 16383] render as "?<rawValue>" —
// matching SIMDFPCanonicalizer's fallback for records it doesn't
// recognize.

/// Canonicalizer for crypto/Apple-extensions records (crypto extensions,
/// PAC standalone, MTE, AMX). The other per-family canonicalizers
/// delegate here when they see a mnemonic in this family's range.
enum CryptoAppleExtensionsCanonicalizer {
    /// Format `instruction` to canonical llvm-mc-compatible disassembly text.
    /// Instructions whose mnemonic is outside the family's mnemonic range
    /// return `"?<rawValue>"` (deterministic non-crashing sentinel — matches
    /// the convention used elsewhere when a canonicalizer is invoked on a
    /// record it cannot render).
    @_effects(readonly)
    @_optimize(speed)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined { return "" }
        guard instruction.mnemonic.rawValue >= 12288, instruction.mnemonic.rawValue <= 16383
        else { return "?\(instruction.mnemonic.rawValue)" }
        // amxUnknownOp renders as its raw-word `.long` operand string
        // alone — its census name ("amx-unknown") is not assembly.
        if instruction.mnemonic == .amxUnknownOp {
            return formatOperands(instruction)
        }
        let mn = instruction.mnemonic.name
        let ops = formatOperands(instruction)
        return ops.isEmpty ? mn : "\(mn) \(ops)"
    }

    /// True iff the mnemonic is in this family's reserved range. Callers
    /// in other canonicalizers (SIMDFP / DPR / DPI / LS) use this as the
    /// guard before delegating here.
    @inlinable
    static func owns(_ mnemonic: Mnemonic) -> Bool {
        mnemonic.rawValue >= 12288 && mnemonic.rawValue <= 16383
    }

    // MARK: - Operand list formatting

    @_effects(readonly)
    private static func formatOperands(_ instruction: Instruction) -> String {
        // Per-mnemonic operand rendering:
        //   IRG with Rm=XZR aliases to the 2-operand form `irg Xd, Xn`.
        //   STG / STZG / ST2G / STZ2G in signed-offset with displacement
        //   0 alias to `mn Xt, [Xn]` (omitting `, #0`).
        //   AMX opcodes 17 (set/clr): operand text is empty.
        //   AMX other opcodes: render the X-register operand from the
        //   5-bit operand subfield.
        switch instruction.mnemonic {
        case .irg:
            return formatIRG(instruction.operands)
        case .stg, .stzg, .st2g, .stz2g:
            return formatMTEStore(instruction.operands)
        case .amxSet, .amxClr:
            return ""
        case .amxUnknownOp:
            // Render as `.long 0xXXXXXXXX` matching the convention llvm-mc
            // uses for unknown 4-byte words. (For amxUnknownOp the operand
            // list contains a single `.amxUnknown(rawFields:)` carrying the
            // full 32-bit encoding.)
            if case let .amxUnknown(rawFields) = instruction.operands.first {
                return formatLongHex(rawFields)
            }
            return formatLongHex(instruction.encoding)
        case .amxLdx, .amxLdy, .amxStx, .amxSty, .amxLdz, .amxStz,
             .amxLdzi, .amxStzi, .amxExtrx, .amxExtry,
             .amxFma64, .amxFms64, .amxFma32, .amxFms32, .amxMac16,
             .amxFma16, .amxFms16, .amxVecint, .amxVecfp, .amxMatint,
             .amxMatfp, .amxGenlut:
            if case let .amxField(f) = instruction.operands.first {
                return xRegisterName(f.operandField)
            }
            return ""
        default:
            return defaultOperandList(instruction.operands)
        }
    }

    @_effects(readonly)
    private static func defaultOperandList(_ operands: Instruction.Operands) -> String {
        var parts: [String] = []
        parts.reserveCapacity(operands.count)
        for op in operands {
            parts.append(formatGenericOperand(op))
        }
        return parts.joined(separator: ", ")
    }

    @_effects(readonly)
    private static func formatGenericOperand(_ operand: Operand) -> String {
        switch operand {
        case let .register(reg):
            reg.name
        case let .vectorRegister(vr):
            vectorRegisterText(vr)
        case let .unsignedImmediate(value, _):
            "#\(value)"
        case let .immediate(value, _):
            "#\(value)"
        case let .memory(mem):
            formatMemoryOperand(mem)
        case let .amxField(field):
            xRegisterName(field.operandField)
        case let .amxUnknown(rawFields):
            formatLongHex(rawFields)
        // This family's decoders never emit these — defensive sentinels
        // so the @frozen Operand switch stays exhaustive.
        case .floatImmediate, .label, .shiftedRegister, .extendedRegister,
             .systemRegister, .conditionCode, .pstateField, .barrierOption,
             .prefetchOperation, .systemOp, .shiftAmount, .pageLabel:
            "?unsupported-operand"
        }
    }

    /// IRG operand rendering — collapse the 3-operand `Xd, Xn, XZR`
    /// form to the 2-operand alias `Xd, Xn` that llvm-mc emits.
    @_effects(readonly)
    private static func formatIRG(_ operands: Instruction.Operands) -> String {
        guard operands.count == 3 else { return defaultOperandList(operands) }
        if case let .register(rm) = operands[2], rm.isZeroRegister {
            return "\(formatGenericOperand(operands[0])), \(formatGenericOperand(operands[1]))"
        }
        return defaultOperandList(operands)
    }

    /// STG / STZG / ST2G / STZ2G rendering — signed-offset with
    /// displacement 0 aliases to `mn Xt, [Xn]` (omitting `, #0`); pre /
    /// post-index always render the imm. The MemoryOperand carries the
    /// writeback kind.
    @_effects(readonly)
    private static func formatMTEStore(_ operands: Instruction.Operands) -> String {
        guard operands.count == 2,
              case let .memory(mem) = operands[1]
        else {
            return defaultOperandList(operands)
        }
        let rt = formatGenericOperand(operands[0])
        let baseText: String = switch mem.base {
        case let .register(reg): reg.name
        case .pc: "pc" // unreachable for MTE stores
        }
        let imm = mem.displacement
        switch mem.writeback {
        case .none:
            // Signed-offset; collapse `, #0` to bare `[Xn]`.
            return imm == 0
                ? "\(rt), [\(baseText)]"
                : "\(rt), [\(baseText), #\(imm)]"
        case .preIndex:
            return "\(rt), [\(baseText), #\(imm)]!"
        case .postIndex:
            return "\(rt), [\(baseText)], #\(imm)"
        }
    }

    /// Format a MemoryOperand. LDG / LDGM / STGM / STZGM use this via
    /// `defaultOperandList`; the MTE-store helper handles STG family.
    @_effects(readonly)
    private static func formatMemoryOperand(_ mem: MemoryOperand) -> String {
        let baseText: String = switch mem.base {
        case let .register(reg): reg.name
        case .pc: "pc"
        }
        let imm = mem.displacement
        switch mem.writeback {
        case .none:
            return imm == 0
                ? "[\(baseText)]"
                : "[\(baseText), #\(imm)]"
        case .preIndex:
            return "[\(baseText), #\(imm)]!"
        case .postIndex:
            return "[\(baseText)], #\(imm)"
        }
    }

    // MARK: - Register name rendering

    @_effects(readonly)
    private static func vectorRegisterText(_ vr: VectorRegisterRef) -> String {
        let n = vr.registerIndex
        switch vr.view {
        case let .full(arrangement):
            return "v\(n).\(arrangementName(arrangement))"
        case let .scalar(size):
            return "\(scalarPrefix(size))\(n)"
        case let .element(arrangement, index):
            return "v\(n).\(scalarSizeName(arrangement.elementSize))[\(index)]"
        case let .elementGroup(elementSize, count, index):
            return "v\(n).\(count)\(scalarSizeName(elementSize))[\(index)]"
        case let .lane(index):
            return "v\(n)[\(index)]"
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func arrangementName(_ a: VectorArrangement) -> String {
        switch a {
        case .b8: "8b"
        case .b16: "16b"
        case .h4: "4h"
        case .h8: "8h"
        case .s2: "2s"
        case .s4: "4s"
        case .d1: "1d"
        case .d2: "2d"
        case .q1: "1q"
        case .h2: "2h"
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func scalarPrefix(_ s: ScalarSize) -> String {
        switch s {
        case .b: "b"
        case .h: "h"
        case .s: "s"
        case .d: "d"
        case .q: "q"
        }
    }

    @inline(__always)
    @_effects(readonly)
    private static func scalarSizeName(_ s: ScalarSize) -> String {
        // Called only from `.element(arrangement, _)` via
        // `arrangement.elementSize`, which never produces `.q` (Q is the
        // 128-bit scalar — no vector arrangement has an element of that
        // size). The `.q` case is folded into the default arm so the
        // switch stays exhaustive without an unreachable arm.
        switch s {
        case .b: "b"
        case .h: "h"
        case .s: "s"
        default: "d"
        }
    }

    /// Render an AMX 5-bit operand subfield as an X register (X0…X30, XZR).
    @inline(__always)
    @_effects(readonly)
    private static func xRegisterName(_ field: UInt8) -> String {
        let n = field & 0x1F
        return n == 31 ? "xzr" : "x\(n)"
    }

    /// Render a 32-bit encoding as `.long 0xXXXXXXXX` matching llvm-mc's
    /// fallback for unknown words. Used for `amxUnknownOp` and as the
    /// fallback rendering for `.amxUnknown(rawFields:)`.
    @inline(__always)
    @_effects(readonly)
    private static func formatLongHex(_ value: UInt32) -> String {
        ".long 0x" + String(value, radix: 16, uppercase: false)
    }

    // MARK: - Mnemonic names
}

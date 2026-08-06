// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Canonical llvm-mc-compatible text formatter for the Data Processing.
enum DPICanonicalizer {
    /// The byte path.
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
        for index in 0 ..< operands.count {
            if index > 0 { out.put(", ") }
            putOperand(mnemonic: instruction.mnemonic, operand: operands[index], into: &out)
        }
    }

    private static func putOperand(
        mnemonic: Mnemonic, operand: Operand, into out: inout TextBytes,
    ) {
        switch operand {
        case let .register(reg):
            RegisterNames.put(reg, into: &out)
        case let .immediate(value, _):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(value)
        case let .unsignedImmediate(value, _):
            out.put(UInt8(ascii: "#"))
            switch mnemonic {
            case .and, .orr, .eor, .ands, .tst:
                out.put("0x")
                out.putHex(value)
            default:
                out.putDecimal(value)
            }
        case let .label(byteOffset):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(byteOffset)
        case let .pageLabel(byteOffset):
            out.put(UInt8(ascii: "#"))
            out.putDecimal(byteOffset)
        case let .shiftAmount(kind, amount):
            putShiftKind(kind, into: &out)
            out.put(" #")
            out.putDecimal(UInt64(amount))
        case .vectorRegister, .floatImmediate, .memory, .shiftedRegister,
             .extendedRegister, .systemRegister, .conditionCode,
             .pstateField, .barrierOption, .prefetchOperation,
             .systemOp, .amxField, .amxUnknown,
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
}

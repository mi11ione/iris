// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer that formats an Instruction into llvm-mc-compatible
// disassembly text: a structural transform from Instruction (domain
// type) to text, consumed by the `DisassemblyText` router behind
// `Instruction.text`.

/// Canonical llvm-mc-compatible disassembly text formatter for the
/// Data Processing — Immediate family. Per-mnemonic format dispatch
/// (hex vs decimal immediates, mixed-width registers for SXTW, etc.).
/// Output is normalized: lowercase, single space between tokens, no
/// leading or trailing whitespace.
enum DPICanonicalizer {
    // Format `instruction` to canonical llvm-mc-compatible disassembly
    // text. Empty string means UNDEFINED (a defensive arm — the text
    // router renders undefined records as `.long` before dispatching
    // here).

    /// The byte path: the same text, written straight into a UTF-8 buffer
    /// instead of assembled through `String`. No intermediate `String` per
    /// operand, no `[String]` of parts and no `joined`, and no
    /// `reserveCapacity` — asking a `String` for capacity forces native
    /// heap storage even for text that would have fitted in the bytes
    /// Swift keeps inline for free.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        // MTE ADDG/SUBG flow through DPI's deferred-op1 branch; route
        // crypto/Apple-extension mnemonics to their own canonicalizer.
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
            // The hex-versus-decimal rule is the same table the `String`
            // path uses; only the emission differs.
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
        // DPI's decoders never produce these — defensive sentinels so
        // the @frozen Operand switch stays exhaustive.
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

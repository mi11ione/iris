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
    /// Format `instruction` to canonical llvm-mc-compatible disassembly
    /// text. Empty string means UNDEFINED (a defensive arm — the text
    /// router renders undefined records as `.long` before dispatching
    /// here).
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined { return "" }
        // MTE ADDG/SUBG flow through DPI's deferred-op1 branch; route
        // crypto/Apple-extension mnemonics to their own canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            return CryptoAppleExtensionsCanonicalizer.format(instruction)
        }
        let mn = instruction.mnemonic.name
        let ops = formatOperands(mnemonic: instruction.mnemonic, operands: instruction.operands)
        return ops.isEmpty ? mn : "\(mn) \(ops)"
    }

    @_effects(readonly)
    private static func formatOperands(mnemonic: Mnemonic, operands: Instruction.Operands) -> String {
        var parts: [String] = []
        parts.reserveCapacity(operands.count)
        for op in operands {
            parts.append(formatOperand(mnemonic: mnemonic, operand: op))
        }
        return parts.joined(separator: ", ")
    }

    @_effects(readonly)
    private static func formatOperand(mnemonic: Mnemonic, operand: Operand) -> String {
        switch operand {
        case let .register(reg):
            reg.name
        case let .immediate(value, _):
            "#\(value)" // signed decimal
        case let .unsignedImmediate(value, _):
            formatUnsignedImmediate(mnemonic: mnemonic, value: value)
        case let .label(byteOffset):
            "#\(byteOffset)"
        case let .pageLabel(byteOffset):
            "#\(byteOffset)"
        case let .shiftAmount(kind, amount):
            "\(shiftKindName(kind)) #\(amount)"
        // DPI's decoders never produce these — defensive sentinels so
        // the @frozen Operand switch stays exhaustive. If one appears,
        // parity tooling will surface a divergence (since llvm-mc will
        // not produce text matching "?...").
        case .vectorRegister, .floatImmediate, .memory, .shiftedRegister,
             .extendedRegister, .systemRegister, .conditionCode,
             .pstateField, .barrierOption, .prefetchOperation,
             .systemOp, .amxField, .amxUnknown:
            "?unsupported-operand"
        }
    }

    /// Hex vs decimal display rule per mnemonic. Matches llvm-mc's
    /// per-mnemonic conventions.
    @_effects(readonly)
    private static func formatUnsignedImmediate(mnemonic: Mnemonic, value: UInt64) -> String {
        // Logical-immediate forms (AND/ORR/EOR/ANDS and TST alias) display
        // as `#0xNN`. MOV (bitmask) uses signed decimal (via .immediate
        // case in the decoder). All other unsigned immediates display
        // as decimal.
        switch mnemonic {
        case .and, .orr, .eor, .ands, .tst:
            "#\(formatHex(value))"
        default:
            "#\(value)"
        }
    }

    /// Format a value as llvm-mc-style hex: lowercase `0x...`, no
    /// leading zeros beyond `0x0`.
    @inline(__always)
    @_effects(readonly)
    private static func formatHex(_ value: UInt64) -> String {
        "0x\(String(value, radix: 16))"
    }

    @inline(__always)
    @_effects(readonly)
    private static func shiftKindName(_ s: ShiftKind) -> String {
        switch s {
        case .lsl: "lsl"
        case .lsr: "lsr"
        case .asr: "asr"
        case .ror: "ror"
        case .msl: "msl"
        }
    }
}

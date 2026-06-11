// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonicalizer that formats an Instruction into llvm-mc-compatible
// disassembly text. Mirrors the DPICanonicalizer and BESCanonicalizer
// pattern: per-mnemonic formatting, lowercase output, single space
// between mnemonic and operand list, comma-space between operands.
//
// Special rules:
//   - SP-extended display collapse (item 5): at 64-bit, `.extendedRegister(Xm, .uxtx, 0)`
//     when (Rd OR Rn) is SP renders as bare `xm` (no extend keyword).
//     SXTX never collapses; UXTW never collapses; non-zero shift never
//     collapses. The rule is checked against the operand list before
//     per-operand rendering.
//   - Conditions follow llvm-mc canonical naming: `cs` → `hs`, `cc` → `lo`.

/// Canonical llvm-mc-compatible disassembly text formatter for the
/// Data Processing — Register family. Output is normalized: lowercase,
/// single space between tokens, no leading or trailing whitespace.
enum DPRCanonicalizer {
    /// Format `instruction` to canonical llvm-mc-compatible disassembly
    /// text. Empty string means UNDEFINED (a defensive arm — the text
    /// router renders undefined records as `.long` before dispatching
    /// here).
    @_effects(readonly)
    @_optimize(speed)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .undefined { return "" }
        // PAC standalone + MTE-DPR records flow through DPR's
        // top-of-method delegation; route them to the crypto canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            return CryptoAppleExtensionsCanonicalizer.format(instruction)
        }
        let mn = instruction.mnemonic.name
        let ops = formatOperands(instruction.operands)
        return ops.isEmpty ? mn : "\(mn) \(ops)"
    }

    @_effects(readonly)
    private static func formatOperands(_ operands: Instruction.Operands) -> String {
        // SP-extended display collapse rule. The "natural"
        // extend for the destination width (UXTX at sf=1, UXTW at sf=0)
        // is elided when a preceding operand is SP at the same width.
        // amount=0 → bare register; amount>0 → "<reg>, lsl #<amount>"
        // (the extend keyword is replaced by `lsl`). SXTX, UXTW-at-sf=1,
        // UXTX-at-sf=0 never collapse — all empirically verified.
        var parts: [String] = []
        parts.reserveCapacity(operands.count)
        for (idx, op) in operands.enumerated() {
            if case let .extendedRegister(reg, extend, shift) = op,
               extendedRegisterCollapses(reg: reg, extend: extend, operands: operands, idx: idx)
            {
                if shift == 0 {
                    parts.append(reg.name)
                } else {
                    parts.append("\(reg.name), lsl #\(shift)")
                }
            } else {
                parts.append(formatOperand(op))
            }
        }
        return parts.joined(separator: ", ")
    }

    /// True iff an `.extendedRegister` operand falls in the SP-extended display-collapse case.
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

    @_effects(readonly)
    private static func formatOperand(_ operand: Operand) -> String {
        switch operand {
        case let .register(reg):
            reg.name
        case let .immediate(value, _):
            "#\(value)"
        case let .unsignedImmediate(value, _):
            "#\(value)"
        case let .shiftedRegister(reg, kind, amount):
            "\(reg.name), \(shiftKindName(kind)) #\(amount)"
        case let .extendedRegister(reg, extend, shift):
            shift == 0
                ? "\(reg.name), \(extendKindName(extend))"
                : "\(reg.name), \(extendKindName(extend)) #\(shift)"
        case let .conditionCode(c):
            conditionName(c)
        // DPR's decoders never produce these — defensive sentinels so the
        // @frozen Operand switch stays exhaustive. A divergence would
        // surface as a text mismatch in the parity sweep.
        case .vectorRegister, .floatImmediate, .label, .memory,
             .systemRegister, .pstateField, .barrierOption,
             .prefetchOperation, .systemOp, .amxField, .amxUnknown,
             .shiftAmount, .pageLabel:
            "?unsupported-operand"
        }
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

    /// Lowercase llvm-mc condition name. `cs` and `cc` render as `hs`
    /// and `lo` respectively (canonical names per ARM ARM aliasing
    /// rules; llvm-mc emits these in disassembly output).
    @inline(__always)
    @_effects(readonly)
    private static func conditionName(_ c: ConditionCode) -> String {
        switch c {
        case .eq: "eq"
        case .ne: "ne"
        case .cs: "hs"
        case .cc: "lo"
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
}

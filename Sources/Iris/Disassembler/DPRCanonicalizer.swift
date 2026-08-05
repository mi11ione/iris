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
    // Format `instruction` to canonical llvm-mc-compatible disassembly
    // text. Empty string means UNDEFINED (a defensive arm — the text
    // router renders undefined records as `.long` before dispatching
    // here).

    /// The byte path — same text, written straight into a UTF-8 buffer.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        // PAC standalone + MTE-DPR records flow through DPR's
        // top-of-method delegation; route them to the crypto canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
            return
        }
        putMnemonic(instruction.mnemonic, into: &out)
        let operands = instruction.operands
        if operands.isEmpty { return }
        out.put(UInt8(ascii: " "))
        // SP-extended display collapse rule. The "natural"
        // extend for the destination width (UXTX at sf=1, UXTW at sf=0)
        // is elided when a preceding operand is SP at the same width.
        // amount=0 → bare register; amount>0 → "<reg>, lsl #<amount>"
        // (the extend keyword is replaced by `lsl`). SXTX, UXTW-at-sf=1,
        // UXTX-at-sf=0 never collapse — all empirically verified.
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
            // `.none` contributes no token, which leaves the trailing
            // separator the `String` path also produced.
            putExtendKind(extend, into: &out)
            if shift != 0 {
                out.put(" #")
                out.putDecimal(UInt64(shift))
            }
        case let .conditionCode(c):
            putConditionName(c, into: &out)
        // DPR's decoders never produce these — defensive sentinels so the
        // @frozen Operand switch stays exhaustive. A divergence would
        // surface as a text mismatch in the parity sweep.
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

    /// Lowercase llvm-mc condition name. `cs` and `cc` render as `hs`
    /// and `lo` respectively (canonical names per ARM ARM aliasing
    /// rules; llvm-mc emits these in disassembly output).
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

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
    /// The byte path — same text, written straight into a UTF-8 buffer.
    ///
    /// The memory operand decomposes into per-piece appends here, which is
    /// the opposite of what a `String` destination wants: against a
    /// `String` every append pays a uniqueness check, a capacity check and
    /// an is-ASCII update, so decomposing loses; against bytes an append is
    /// a bounds check and a store, so it wins. The eager
    /// `reserveCapacity(count * 12)` the `String` path opened with is gone
    /// with it — asking a `String` for 24-plus bytes forces native heap
    /// storage even for the majority of instructions whose text fits in
    /// what Swift keeps inline for free.
    @_optimize(speed)
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        if instruction.mnemonic == .undefined { return }
        // MTE L/S flows through LoadsAndStoresDecoder's case 0b011001
        // delegation; route crypto-range mnemonics to their canonicalizer.
        if CryptoAppleExtensionsCanonicalizer.owns(instruction.mnemonic) {
            CryptoAppleExtensionsCanonicalizer.format(instruction, into: &out)
            return
        }
        putMnemonic(instruction.mnemonic, into: &out)
        // FEAT_MOPS CPY/SET carry a `[Xd]!, …` / `…, Xn!` syntax with
        // trailing `!` on registers/brackets that the generic operand
        // formatter cannot express; render it directly. The separator is
        // emitted unconditionally for these two forms, matching the
        // `String` path, which interpolated a possibly-empty operand text.
        let r = instruction.mnemonic.rawValue
        if (2330 ... 2449).contains(r) {
            out.put(UInt8(ascii: " "))
            putMOPSOperands(instruction, into: &out)
            return
        }
        // FEAT_RPRES RPRFM's first operand is a 6-bit range-prefetch op with
        // a small symbolic-name set (others rendered `#N`).
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

    /// Render MOPS operands. CPY/CPYF (rawValue 2330..2425) →
    /// `[Xd]!, [Xs]!, Xn!`; SET/SETG (2426..2449) → `[Xd]!, Xn!, Xs`.
    private static func putMOPSOperands(_ instruction: Instruction, into out: inout TextBytes) {
        let ops = instruction.operands
        guard ops.count == 3,
              case let .register(r0) = ops[0],
              case let .register(r1) = ops[1],
              case let .register(r2) = ops[2]
        else { return }
        if instruction.mnemonic.rawValue <= 2425 {
            // CPY/CPYF: dest and source are address registers (bracketed),
            // count register carries a trailing `!`.
            out.put(UInt8(ascii: "["))
            RegisterNames.put(r0, into: &out)
            out.put("]!, [")
            RegisterNames.put(r1, into: &out)
            out.put("]!, ")
            RegisterNames.put(r2, into: &out)
            out.put(UInt8(ascii: "!"))
            return
        }
        // SET/SETG: dest address bracketed, count register `!`, data register bare.
        out.put(UInt8(ascii: "["))
        RegisterNames.put(r0, into: &out)
        out.put("]!, ")
        RegisterNames.put(r1, into: &out)
        out.put("!, ")
        RegisterNames.put(r2, into: &out)
    }

    /// Render RPRFM operands: `<prfop>, Xm, [Xn]`. The 6-bit prfop has
    /// symbolic names only for {0,1,4,5}; all others render as `#N`.
    private static func putRPRFMOperands(
        _ ops: Instruction.Operands, into out: inout TextBytes,
    ) {
        guard ops.count == 3,
              case let .immediate(prfop, _) = ops[0]
        else {
            // The decoder always emits the three-operand shape, so this is
            // reached only by a hand-built record. Iterating rather than
            // indexing keeps it total for any operand count without a
            // bounds check no real record can exercise.
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
        // L/S decoders never emit these cases; the arm exists so the
        // `Operand` switch stays exhaustive without trapping.
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
    /// PC-base literal loads render as `#<displacement>` (no brackets).
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

        // `mem.shift == 0xFF` is the "no #amount displayed" sentinel set
        // by LoadStoreRegisterOffsetDecode for UXTW/SXTW/SXTX with S=0.
        // `.none` extend means LSL/UXTX collapse to bare `[Rn, Xm]`,
        // matching llvm-mc; other extends keep their keyword.
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
            // Drop `#0` for every `.none` writeback memory
            // operand — pair forms included. llvm-mc disassembles
            // `ldp x0, x1, [x2, #0]` as `ldp x0, x1, [x2]`.
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

    /// Render a ``PrefetchOperation`` as its symbolic mnemonic
    /// (pldl1keep .. pstl3strm) or `#<N>` for reserved encodings.
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

    /// The `, <extend>{ #<amount>}` tail of a register-offset memory
    /// operand. `.none` is the LSL/UXTX collapse — the whole tail is
    /// absent, which is the common case rather than a defensive one, so
    /// the early return sits inside the switch rather than behind a
    /// caller-side guard that would leave this arm unreachable.
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
        // 0xFF is the "no #amount displayed" sentinel.
        if mem.shift != 0xFF {
            out.put(" #")
            out.putDecimal(UInt64(mem.shift))
        }
    }
}

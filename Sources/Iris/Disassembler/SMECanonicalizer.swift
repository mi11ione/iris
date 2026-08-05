// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Canonical llvm-mc-parity text for SME-core records. Mirrors
// the SVE canonicalizer conventions: lowercase, `, `-joined operands. A
// scalable-tier hole never reaches here — the text router renders it as
// `.long` before dispatching. The SME-specific rules (every one probe-pinned against
// llvm-mc 22.1.4) are: MOVA renders `mov` (the always-preferred alias); a ZA
// tile slice `za<t>{h|v}.<T>[Wv, off]` is braced only inside an LD1/ST1 (the
// forms with a memory operand); LD1 governing predicates render `/z`, ST1 bare;
// the register-offset shift is the access-element log2 size (none for `.b`);
// LDR/STR ZA print the vector-select offset always but drop a zero memory
// offset; and ZERO renders the imm8 mask as the shortest uniform tile list,
// with llvm's comma-no-space quirk on the multi-`.s` alias lists.

/// Formats SME-core records exactly as llvm-mc renders them.
enum SMECanonicalizer {
    /// The byte path — rendered straight into a UTF-8 buffer.
    static func format(_ instruction: Instruction, into out: inout TextBytes) {
        let ops = instruction.operands
        if instruction.mnemonic == .zero {
            putZero(ops, into: &out)
            return
        }
        // This family's own table: a mnemonic from outside the group
        // renders nothing rather than the spelling another family owns.
        if let spelling = name(instruction.mnemonic) { out.put(spelling) }
        if ops.isEmpty { return }
        // A tile slice inside a memory-bearing instruction renders braced.
        var braceSlice = false
        for op in ops where {
            if case .scalableMemory = op { true } else { false }
        }() {
            braceSlice = true
            break
        }
        out.put(UInt8(ascii: " "))
        for i in 0 ..< ops.count {
            if i > 0 { out.put(", ") }
            put(ops[i], braceSlice: braceSlice, into: &out)
        }
    }

    // MARK: per-operand rendering

    private static func put(_ op: Operand, braceSlice: Bool, into out: inout TextBytes) {
        switch op {
        case let .zaTile(index, element):
            putZATile(index: index, element: element, into: &out)
        case let .zaTileSlice(s):
            if braceSlice { out.put(UInt8(ascii: "{")) }
            putTileSlice(s, into: &out)
            if braceSlice { out.put(UInt8(ascii: "}")) }
        case let .zaArrayVector(v):
            out.put("za")
            if let el = v.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
            out.put(UInt8(ascii: "["))
            putSelect(v.selectRegister, into: &out)
            out.put(", ")
            out.putDecimal(UInt64(v.offset))
            out.put(UInt8(ascii: "]"))
        case let .scalablePredicate(p):
            out.put(UInt8(ascii: "p"))
            out.putDecimal(UInt64(p.registerIndex))
            switch p.qualifier {
            case .zeroing: out.put("/z")
            case .merging: out.put("/m")
            case .none: break
            }
        case let .scalableVector(v):
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(v.registerIndex))
            if let el = v.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
        case let .scalableMemory(m):
            putMemory(m, into: &out)
        default:
            out.put("?")
        }
    }

    // MARK: ZERO

    private static func putZero(_ operands: Instruction.Operands, into out: inout TextBytes) {
        if operands.isEmpty {
            out.put("zero {}")
            return
        }
        if operands.count == 1, case .zaTile(_, .none) = operands[0] {
            out.put("zero {za}")
            return
        }
        var allS = operands.count >= 2
        for op in operands {
            guard case let .zaTile(_, element) = op else { continue }
            if element != .some(.s) { allS = false }
        }
        // The equal-nibble `.s` alias lists render comma-no-space (an llvm
        // InstAlias-string artifact); generic `.d` lists use comma-space.
        out.put("zero {")
        var first = true
        for op in operands {
            guard case let .zaTile(index, element) = op else { continue }
            if !first { out.put(allS ? "," : ", ") }
            first = false
            putZATile(index: index, element: element, into: &out)
        }
        out.put(UInt8(ascii: "}"))
    }

    // MARK: text helpers

    private static func putZATile(index: UInt8, element: ScalarSize?, into out: inout TextBytes) {
        guard let element else {
            out.put("za")
            return
        }
        out.put("za")
        out.putDecimal(UInt64(index))
        out.put(UInt8(ascii: "."))
        putSuffix(element, into: &out)
    }

    private static func putTileSlice(_ s: ZATileSliceOperand, into out: inout TextBytes) {
        out.put("za")
        out.putDecimal(UInt64(s.tileIndex))
        out.put(s.direction == .vertical ? "v" : "h")
        out.put(UInt8(ascii: "."))
        putSuffix(s.element, into: &out)
        out.put(UInt8(ascii: "["))
        putSelect(s.selectRegister, into: &out)
        out.put(", ")
        out.putDecimal(UInt64(s.offset))
        out.put(UInt8(ascii: "]"))
    }

    private static func putMemory(_ m: ScalableMemoryOperand, into out: inout TextBytes) {
        out.put(UInt8(ascii: "["))
        switch m.base {
        case let .gpr(r):
            putRegister64(r, into: &out)
        case let .vector(v):
            out.put(UInt8(ascii: "z"))
            out.putDecimal(UInt64(v.registerIndex))
            if let el = v.element {
                out.put(UInt8(ascii: "."))
                putSuffix(el, into: &out)
            }
        }
        if let si = m.scalarIndex {
            out.put(", ")
            putRegister64(si, into: &out)
            if m.scaleShift > 0 {
                out.put(", lsl #")
                out.putDecimal(UInt64(m.scaleShift))
            }
        }
        if m.displacement != 0 {
            out.put(", #")
            out.putDecimal(Int64(m.displacement))
            if m.mulVL { out.put(", mul vl") }
        }
        out.put(UInt8(ascii: "]"))
    }

    /// A select register `Wv` (`W12`-`W15`) renders `w<index>`.
    @inline(__always)
    private static func putSelect(_ r: RegisterRef, into out: inout TextBytes) {
        out.put(UInt8(ascii: "w"))
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    /// A GPR in an address renders 64-bit (`x<n>` / `sp`).
    @inline(__always)
    private static func putRegister64(_ r: RegisterRef, into out: inout TextBytes) {
        if r.canonicalIndex == 31 {
            out.put("sp")
            return
        }
        out.put(UInt8(ascii: "x"))
        out.putDecimal(UInt64(r.canonicalIndex))
    }

    @inline(__always)
    private static func putSuffix(_ s: ScalarSize, into out: inout TextBytes) {
        switch s {
        case .b: out.put("b")
        case .h: out.put("h")
        case .s: out.put("s")
        case .d: out.put("d")
        case .q: out.put("q")
        }
    }

    /// The rendered spelling of an SME-core mnemonic. `zero` renders through
    /// ``formatZero(_:)`` from ``format(_:)`` before reaching here, but is
    /// still mapped so this stays a total naming table for ``Mnemonic/name``.
    @_effects(readonly)
    static func name(_ m: Mnemonic) -> StaticString? {
        switch m {
        case .zero: "zero"
        case .mov: "mov"
        case .addha: "addha"; case .addva: "addva"
        case .fmopa: "fmopa"; case .fmops: "fmops"
        case .bfmopa: "bfmopa"; case .bfmops: "bfmops"
        case .smopa: "smopa"; case .smops: "smops"
        case .sumopa: "sumopa"; case .sumops: "sumops"
        case .usmopa: "usmopa"; case .usmops: "usmops"
        case .umopa: "umopa"; case .umops: "umops"
        case .bmopa: "bmopa"; case .bmops: "bmops"
        case .ld1b: "ld1b"; case .ld1h: "ld1h"; case .ld1w: "ld1w"; case .ld1d: "ld1d"; case .ld1q: "ld1q"
        case .st1b: "st1b"; case .st1h: "st1h"; case .st1w: "st1w"; case .st1d: "st1d"; case .st1q: "st1q"
        case .ldr: "ldr"; case .str: "str"
        default: ""
        }
    }
}

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
    @_effects(readonly)
    static func format(_ instruction: Instruction) -> String {
        if instruction.mnemonic == .zero { return formatZero(Array(instruction.operands)) }
        let mnemonic = name(instruction.mnemonic)
        if Array(instruction.operands).isEmpty { return mnemonic }
        let braceSlice = Array(instruction.operands).contains { if case .scalableMemory = $0 { true } else { false } }
        var parts: [String] = []
        parts.reserveCapacity(Array(instruction.operands).count)
        for op in Array(instruction.operands) {
            parts.append(render(op, braceSlice: braceSlice))
        }
        return mnemonic + " " + parts.joined(separator: ", ")
    }

    // MARK: per-operand rendering

    @_effects(readonly)
    private static func render(_ op: Operand, braceSlice: Bool) -> String {
        switch op {
        case let .zaTile(index, element):
            return zaTileText(index: index, element: element)
        case let .zaTileSlice(s):
            let core = tileSliceText(s)
            return braceSlice ? "{\(core)}" : core
        case let .zaArrayVector(v):
            let suffixText = v.element.map { ".\(suffix($0))" } ?? ""
            return "za\(suffixText)[\(selectText(v.selectRegister)), \(v.offset)]"
        case let .scalablePredicate(p):
            var s = "p\(p.registerIndex)"
            switch p.qualifier {
            case .zeroing: s += "/z"
            case .merging: s += "/m"
            case .none: break
            }
            return s
        case let .scalableVector(v):
            let suffixText = v.element.map { ".\(suffix($0))" } ?? ""
            return "z\(v.registerIndex)\(suffixText)"
        case let .scalableMemory(m):
            return memoryText(m)
        default:
            return "?"
        }
    }

    // MARK: ZERO

    @_effects(readonly)
    private static func formatZero(_ operands: [Operand]) -> String {
        if operands.isEmpty { return "zero {}" }
        if operands.count == 1, case .zaTile(_, .none) = operands[0] { return "zero {za}" }
        var allS = operands.count >= 2
        var tiles: [String] = []
        tiles.reserveCapacity(operands.count)
        for op in operands {
            guard case let .zaTile(index, element) = op else { continue }
            if element != .some(.s) { allS = false }
            tiles.append(zaTileText(index: index, element: element))
        }
        // The equal-nibble `.s` alias lists render comma-no-space (an llvm
        // InstAlias-string artifact); generic `.d` lists use comma-space.
        return "zero {" + tiles.joined(separator: allS ? "," : ", ") + "}"
    }

    // MARK: text helpers

    @_effects(readonly)
    private static func zaTileText(index: UInt8, element: ScalarSize?) -> String {
        guard let element else { return "za" }
        return "za\(index).\(suffix(element))"
    }

    @_effects(readonly)
    private static func tileSliceText(_ s: ZATileSliceOperand) -> String {
        let dir = s.direction == .vertical ? "v" : "h"
        return "za\(s.tileIndex)\(dir).\(suffix(s.element))[\(selectText(s.selectRegister)), \(s.offset)]"
    }

    @_effects(readonly)
    private static func memoryText(_ m: ScalableMemoryOperand) -> String {
        var s = "["
        switch m.base {
        case let .gpr(r): s += registerText64(r)
        case let .vector(v): s += "z\(v.registerIndex)" + (v.element.map { ".\(suffix($0))" } ?? "")
        }
        if let si = m.scalarIndex {
            s += ", " + registerText64(si)
            if m.scaleShift > 0 { s += ", lsl #\(m.scaleShift)" }
        }
        if m.displacement != 0 {
            s += ", #\(m.displacement)"
            if m.mulVL { s += ", mul vl" }
        }
        s += "]"
        return s
    }

    /// A select register `Wv` (`W12`-`W15`) renders `w<index>`.
    @_effects(readonly)
    private static func selectText(_ r: RegisterRef) -> String {
        "w\(r.canonicalIndex)"
    }

    /// A GPR in an address renders 64-bit (`x<n>` / `sp`).
    @_effects(readonly)
    private static func registerText64(_ r: RegisterRef) -> String {
        if r.canonicalIndex == 31 { return "sp" }
        return "x\(r.canonicalIndex)"
    }

    @inline(__always) @_effects(readonly)
    private static func suffix(_ s: ScalarSize) -> String {
        switch s { case .b: "b"; case .h: "h"; case .s: "s"; case .d: "d"; case .q: "q" }
    }

    /// The rendered spelling of an SME-core mnemonic. `zero` renders through
    /// ``formatZero(_:)`` from ``format(_:)`` before reaching here, but is
    /// still mapped so this stays a total naming table for ``Mnemonic/name``.
    @_effects(readonly)
    static func name(_ m: Mnemonic) -> String {
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

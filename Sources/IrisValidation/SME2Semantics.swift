// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// the SME2 semantic checker. An independent re-derivation of
// the classification a decoded SME2 record must carry, compared to
// what the decoder tagged. It does not re-run the decoder's field extraction
// (the exhaustive text sweep already proves the operand structure); instead
// it verifies the semantic invariants that never appear in the rendered text
// — category, branch/flag/memory/ordering classification, and the ZA/ZT0
// register-touch consistency between the operand list and the scalable
// read/write sets. The validator runs it on every in-scope decoded record;
// any mismatch is a gating divergence.

// Checks the semantic classification of a SME2 SME2 record against the
// architectural model, independently of the decoder.

import Iris

public enum SME2SemanticChecker {
    /// A single semantic mismatch — the field, the decoder's value, and the
    /// independently-derived expectation.
    public struct Issue: Sendable {
        public let field: String
        public let actual: String
        public let expected: String
    }

    /// Verify `draft`'s semantic tags. Returns the first mismatch, or `nil`
    /// when the record is semantically consistent with the model.
    @_optimize(speed)
    public static func verify(draft: Instruction) -> Issue? {
        // UNDEFINED holes carry no operands and their category is checked by
        // region below; nothing else to re-derive.
        let region = (draft.encoding >> 25) & 0xF
        let expectedCategory: Category = region == 0b0010 ? .sve : .sme
        if draft.category != expectedCategory {
            return Issue(field: "category", actual: "\(draft.category)", expected: "\(expectedCategory)")
        }
        guard draft.mnemonic != .undefined else { return nil }

        // Universal invariants: no branch, no ordering, no NZCV except WHILE.
        if draft.branchClass != .none {
            return Issue(field: "branchClass", actual: "\(draft.branchClass)", expected: "none")
        }
        if !draft.memoryOrdering.isEmpty {
            return Issue(field: "memoryOrdering", actual: "\(draft.memoryOrdering)", expected: "[]")
        }
        let expectedFlag: FlagEffect = isWhile(draft.mnemonic) ? .nzcv : .none
        if draft.flagEffect != expectedFlag {
            return Issue(field: "flagEffect", actual: "\(draft.flagEffect)", expected: "\(expectedFlag)")
        }

        // Memory access follows the mnemonic (loads/stores of a Z-list or ZT0).
        let expectedMemory = memoryAccess(draft.mnemonic)
        if draft.memoryAccess != expectedMemory {
            return Issue(field: "memoryAccess", actual: "\(draft.memoryAccess)", expected: "\(expectedMemory)")
        }

        // ZA is touched iff the record carries a ZA operand (array vector,
        // tile, or tile slice).
        let hasZAOperand = draft.operands.contains { operand in
            switch operand {
            case .zaArrayVector, .zaTile, .zaTileSlice: true
            default: false
            }
        }
        let touchesZA = !draft.scalableReads.zaMask.isEmpty || !draft.scalableWrites.zaMask.isEmpty
        if hasZAOperand != touchesZA {
            return Issue(field: "za", actual: "touched=\(touchesZA)", expected: "operand=\(hasZAOperand)")
        }

        // ZT0 is touched iff the record carries a ZT0 operand.
        let hasZT0Operand = draft.operands.contains { operand in
            if case .zt0 = operand { true } else { false }
        }
        let touchesZT0 = draft.scalableReads.containsZT0 || draft.scalableWrites.containsZT0
        if hasZT0Operand != touchesZT0 {
            return Issue(field: "zt0", actual: "touched=\(touchesZT0)", expected: "operand=\(hasZT0Operand)")
        }

        // Streaming mode: every SME2 record is streaming-gated except the
        // non-streaming-safe `ZT0` fill/spill/zero trio (LDR/STR ZT0, ZERO
        // {zt0}) — the only `IsNonStreamingSafe` records in the tblgen gates.
        let nonStreamingSafe = draft.mnemonic == .ldr || draft.mnemonic == .str
            || (draft.mnemonic == .zero && hasZT0Operand)
        if draft.scalableEffect.contains(.readsStreamingMode) == nonStreamingSafe {
            return Issue(
                field: "readsStreamingMode",
                actual: "\(draft.scalableEffect.contains(.readsStreamingMode))",
                expected: "\(!nonStreamingSafe)",
            )
        }

        // Partial write: a statically-partial destination survives — any ZA
        // write (a dynamic slice/tile) or a MOVT `ZT0`-slice insert. Full
        // writes (Z lists, predicates, GPRs, the full-`ZT0` LDR/ZERO) are not.
        let writesZA = !draft.scalableWrites.zaMask.isEmpty
        let movtInsert = draft.mnemonic == .movt && draft.scalableWrites.containsZT0
        let expectPartial = writesZA || movtInsert
        if draft.scalableEffect.contains(.partialWrite) != expectPartial {
            return Issue(
                field: "partialWrite",
                actual: "\(draft.scalableEffect.contains(.partialWrite))",
                expected: "\(expectPartial)",
            )
        }

        // Non-temporal iff LDNT1/STNT1; and SME2 never toggles the streaming /
        // ZA-enable state (those are the SMSTART/SMSTOP).
        let expectNonTemporal = isNonTemporal(draft.mnemonic)
        if draft.scalableEffect.contains(.nonTemporal) != expectNonTemporal {
            return Issue(
                field: "nonTemporal",
                actual: "\(draft.scalableEffect.contains(.nonTemporal))",
                expected: "\(expectNonTemporal)",
            )
        }
        if draft.scalableEffect.contains(.writesStreamingMode)
            || draft.scalableEffect.contains(.writesZAEnable)
        {
            return Issue(field: "writesMode", actual: "set", expected: "unset")
        }

        return nil
    }

    /// The non-temporal multi-vector loads/stores.
    @inline(__always)
    private static func isNonTemporal(_ m: Mnemonic) -> Bool {
        switch m {
        case .ldnt1b, .ldnt1h, .ldnt1w, .ldnt1d, .stnt1b, .stnt1h, .stnt1w, .stnt1d: true
        default: false
        }
    }

    /// The eight predicate-as-counter `WHILE` mnemonics set NZCV; nothing else
    /// in the family does.
    @inline(__always)
    private static func isWhile(_ m: Mnemonic) -> Bool {
        switch m {
        case .whilege, .whilegt, .whilehi, .whilehs,
             .whilele, .whilelt, .whilelo, .whilels: true
        default: false
        }
    }

    /// The memory-access class implied by a mnemonic — the multi-vector
    /// loads/stores and the `ZT0` fill/spill (`LDR`/`STR`).
    @inline(__always)
    private static func memoryAccess(_ m: Mnemonic) -> MemoryAccess {
        switch m {
        case .ld1b, .ld1h, .ld1w, .ld1d, .ldnt1b, .ldnt1h, .ldnt1w, .ldnt1d, .ldr: .load
        case .st1b, .st1h, .st1w, .st1d, .stnt1b, .stnt1h, .stnt1w, .stnt1d, .str: .store
        default: .none
        }
    }
}

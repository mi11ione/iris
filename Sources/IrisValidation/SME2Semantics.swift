// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

public enum SME2SemanticChecker {
    /// A single semantic mismatch.
    public struct Issue: Sendable {
        public let field: String
        public let actual: String
        public let expected: String
    }

    /// Verify `draft`'s semantic tags.
    @_optimize(speed)
    public static func verify(draft: Instruction) -> Issue? {
        let region = (draft.encoding >> 25) & 0xF
        let expectedCategory: Category = region == 0b0010 ? .sve : .sme
        if draft.category != expectedCategory {
            return Issue(field: "category", actual: "\(draft.category)", expected: "\(expectedCategory)")
        }
        guard draft.mnemonic != .undefined else { return nil }

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

        let expectedMemory = memoryAccess(draft.mnemonic)
        if draft.memoryAccess != expectedMemory {
            return Issue(field: "memoryAccess", actual: "\(draft.memoryAccess)", expected: "\(expectedMemory)")
        }

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

        let hasZT0Operand = draft.operands.contains { operand in
            if case .zt0 = operand { true } else { false }
        }
        let touchesZT0 = draft.scalableReads.containsZT0 || draft.scalableWrites.containsZT0
        if hasZT0Operand != touchesZT0 {
            return Issue(field: "zt0", actual: "touched=\(touchesZT0)", expected: "operand=\(hasZT0Operand)")
        }

        let nonStreamingSafe = draft.mnemonic == .ldr || draft.mnemonic == .str
            || (draft.mnemonic == .zero && hasZT0Operand)
        if draft.scalableEffect.contains(.readsStreamingMode) == nonStreamingSafe {
            return Issue(
                field: "readsStreamingMode",
                actual: "\(draft.scalableEffect.contains(.readsStreamingMode))",
                expected: "\(!nonStreamingSafe)",
            )
        }

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

    /// The memory-access class implied by a mnemonic.
    @inline(__always)
    private static func memoryAccess(_ m: Mnemonic) -> MemoryAccess {
        switch m {
        case .ld1b, .ld1h, .ld1w, .ld1d, .ldnt1b, .ldnt1h, .ldnt1w, .ldnt1d, .ldr: .load
        case .st1b, .st1h, .st1w, .st1d, .stnt1b, .stnt1h, .stnt1w, .stnt1d, .str: .store
        default: .none
        }
    }
}

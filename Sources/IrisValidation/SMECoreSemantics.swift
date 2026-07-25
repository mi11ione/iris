// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// semantic-attribute checker for SME core records.
// Independently re-derives the expected semantic classification from the
// mnemonic and the (text-validated) operand list and compares it to what the
// decoder produced, so a decode that renders the right text but mis-tags a
// memory-access kind, a streaming/partial-write effect, the ZA read/write
// overlap mask, or the slice-select GPR read is still caught.
// The ZA-overlap write model (acceptance) is the load-bearing
// SME check: the expected ZA mask is recomputed from the operands and compared
// bit-for-bit against `scalableReads`/`scalableWrites`.

// A semantic mismatch between a decoded SME record and the independently
// derived expectation.

import Iris

public struct SMECoreSemanticIssue: Sendable, Hashable {
    public let field: String
    public let actual: String
    public let expected: String

    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Verifies SME-core records against the independently derived semantic model.
public enum SMECoreSemanticChecker {
    /// The SME-core instruction families, distinguished by mnemonic (and, for
    /// `mov`, by operand shape). Each fixes the memory kind, the effect flags,
    /// and which ZA operand is read vs written.
    public enum Family {
        case outerProduct, addHV, movaInsert, movaExtract
        case ld1, st1, ldrZA, strZA, zero
    }

    @_optimize(speed)
    @_effects(readonly)
    public static func verify(draft: Instruction) -> SMECoreSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }

        // Universal invariants: category .sme; no branch, memory
        // ordering, or flag effect.
        if draft.category != .sme {
            return issue("category", draft.category, Category.sme)
        }
        if draft.branchClass != .none {
            return issue("branchClass", draft.branchClass, BranchClass.none)
        }
        if draft.flagEffect != .none {
            return issue("flagEffect", draft.flagEffect, FlagEffect.none)
        }
        if draft.memoryOrdering != [] {
            return SMECoreSemanticIssue(field: "memoryOrdering", actual: "\(draft.memoryOrdering.rawValue)", expected: "0")
        }

        guard let family = family(of: draft) else {
            return SMECoreSemanticIssue(field: "family", actual: "\(draft.mnemonic.rawValue)", expected: "a known SME-core family")
        }

        // Memory-access kind.
        let expectedAccess = expectedMemoryAccess(family)
        if draft.memoryAccess != expectedAccess {
            return issue("memoryAccess", draft.memoryAccess, expectedAccess)
        }

        // Effect flags: no in-scope SME-core decode writes streaming
        // mode or ZA-enable (those live on the SMSTART/SMSTOP records).
        if let flagIssue = checkFlag(draft, .readsStreamingMode, "readsStreamingMode", expectsReadsStreaming(family)) {
            return flagIssue
        }
        if let flagIssue = checkFlag(draft, .partialWrite, "partialWrite", expectsPartialWrite(family)) {
            return flagIssue
        }
        if draft.scalableEffect.contains(.writesStreamingMode) {
            return SMECoreSemanticIssue(field: "writesStreamingMode", actual: "set", expected: "unset")
        }
        if draft.scalableEffect.contains(.writesZAEnable) {
            return SMECoreSemanticIssue(field: "writesZAEnable", actual: "set", expected: "unset")
        }

        // ZA overlap read/write masks (acceptance).
        let (expectedRead, expectedWrite) = expectedZAMasks(family, Array(draft.operands))
        if draft.scalableReads.zaMask.bits != expectedRead {
            return maskIssue("scalableReads.za", draft.scalableReads.zaMask.bits, expectedRead)
        }
        if draft.scalableWrites.zaMask.bits != expectedWrite {
            return maskIssue("scalableWrites.za", draft.scalableWrites.zaMask.bits, expectedWrite)
        }

        // The slice-select GPR Wv is a semantic read on every tile-slice /
        // array-vector access — a classification the text renders
        // but the read-set could still drop.
        if familyTouchesSelect(family), let sel = selectRegisterIndex(Array(Array(draft.operands))) {
            if !draft.semanticReads.contains(RegisterRef.x(sel)) {
                return SMECoreSemanticIssue(field: "semanticReads.selectRegister", actual: "missing w\(sel)", expected: "w\(sel) read")
            }
        }
        return nil
    }

    // MARK: family classification

    @_effects(readonly)
    public static func family(of draft: Instruction) -> Family? {
        switch draft.mnemonic {
        case .fmopa, .fmops, .bfmopa, .bfmops, .smopa, .smops,
             .sumopa, .sumops, .usmopa, .usmops, .umopa, .umops, .bmopa, .bmops:
            return .outerProduct
        case .addha, .addva:
            return .addHV
        case .zero:
            return .zero
        case .ld1b, .ld1h, .ld1w, .ld1d, .ld1q:
            return .ld1
        case .st1b, .st1h, .st1w, .st1d, .st1q:
            return .st1
        case .ldr:
            return .ldrZA
        case .str:
            return .strZA
        case .mov:
            // Insert writes a tile slice (operand 0); extract writes a Z vector.
            if case .zaTileSlice = Array(draft.operands).first { return .movaInsert }
            return .movaExtract
        default:
            return nil
        }
    }

    // MARK: per-family expectations

    @_effects(readonly)
    public static func expectedMemoryAccess(_ family: Family) -> MemoryAccess {
        switch family {
        case .ld1, .ldrZA: .load
        case .st1, .strZA: .store
        default: .none
        }
    }

    /// LD1/ST1/MOVA/outer-products/ADDHA/ADDVA depend on `PSTATE.SM`; LDR/STR
    /// ZA and ZERO are non-streaming-safe.
    @_effects(readonly)
    public static func expectsReadsStreaming(_ family: Family) -> Bool {
        switch family {
        case .ldrZA, .strZA, .zero: false
        default: true
        }
    }

    /// Every dynamic-slice / predicated-merge ZA or Z write is partial; stores
    /// have no vector destination and ZERO is an exact full-def.
    @_effects(readonly)
    public static func expectsPartialWrite(_ family: Family) -> Bool {
        switch family {
        case .st1, .strZA, .zero: false
        default: true
        }
    }

    @_effects(readonly)
    public static func familyTouchesSelect(_ family: Family) -> Bool {
        switch family {
        case .outerProduct, .addHV, .zero: false
        default: true // mova / ld1 / st1 / ldrZA / strZA carry Wv
        }
    }

    /// The expected `(ZA read, ZA write)` residue masks, recomputed from the
    /// ZA operand — the exact overlap model of
    @_effects(readonly)
    public static func expectedZAMasks(_ family: Family, _ operands: [Operand]) -> (read: UInt16, write: UInt16) {
        switch family {
        case .outerProduct, .addHV:
            let m = firstZAMask(operands) // accumulate: read + write the tile
            return (m, m)
        case .movaInsert:
            let m = firstZAMask(operands) // merging: read + write the tile
            return (m, m)
        case .movaExtract:
            return (tileSliceMask(operands), 0) // reads the source tile only
        case .ld1:
            return (0, firstZAMask(operands)) // writes the loaded tile slice
        case .st1:
            return (firstZAMask(operands), 0) // reads the stored tile slice
        case .ldrZA:
            return (0, 0xFFFF) // writes the whole array (dynamic row)
        case .strZA:
            return (0xFFFF, 0) // reads the whole array
        case .zero:
            return (0, zeroMask(operands)) // exact write of the listed tiles
        }
    }

    // MARK: ZA-mask helpers

    /// The ZA residue mask of the first ZA operand (`zaTile` / `zaTileSlice` /
    /// `zaArrayVector`), or 0 if none.
    @_effects(readonly)
    public static func firstZAMask(_ operands: [Operand]) -> UInt16 {
        for op in operands {
            if let m = zaMask(op) { return m }
        }
        return 0
    }

    /// The ZA residue mask of the `zaTileSlice` operand specifically (MOVA
    /// extract, where the tile is not the first operand).
    @_effects(readonly)
    public static func tileSliceMask(_ operands: [Operand]) -> UInt16 {
        for op in operands {
            if case let .zaTileSlice(s) = op { return s.zaMask.bits }
        }
        return 0
    }

    /// The union of every `zaTile` operand's mask — the ZERO write set.
    @_effects(readonly)
    public static func zeroMask(_ operands: [Operand]) -> UInt16 {
        var bits: UInt16 = 0
        for op in operands {
            if case let .zaTile(index, element) = op {
                bits |= (element.map { ZATileMask(tile: index, element: $0) } ?? .whole).bits
            }
        }
        return bits
    }

    @_effects(readonly)
    public static func zaMask(_ op: Operand) -> UInt16? {
        switch op {
        case let .zaTile(index, element):
            (element.map { ZATileMask(tile: index, element: $0) } ?? .whole).bits
        case let .zaTileSlice(s):
            s.zaMask.bits
        case let .zaArrayVector(v):
            v.zaMask.bits
        default:
            nil
        }
    }

    /// The GPR index of the slice-select `Wv` carried by the ZA operand.
    @_effects(readonly)
    public static func selectRegisterIndex(_ operands: [Operand]) -> UInt8? {
        for op in operands {
            switch op {
            case let .zaTileSlice(s): return s.selectRegister.canonicalIndex
            case let .zaArrayVector(v): return v.selectRegister.canonicalIndex
            default: continue
            }
        }
        return nil
    }

    // MARK: issue builders

    @inline(__always)
    public static func checkFlag(_ draft: Instruction, _ flag: ScalableEffect, _ field: String, _ expectSet: Bool) -> SMECoreSemanticIssue? {
        if draft.scalableEffect.contains(flag) != expectSet {
            return SMECoreSemanticIssue(field: field, actual: expectSet ? "unset" : "set", expected: expectSet ? "set" : "unset")
        }
        return nil
    }

    @inline(__always)
    public static func issue(_ field: String, _ actual: some RawRepresentable<UInt8>, _ expected: some RawRepresentable<UInt8>) -> SMECoreSemanticIssue {
        SMECoreSemanticIssue(field: field, actual: "\(actual.rawValue)", expected: "\(expected.rawValue)")
    }

    @inline(__always)
    public static func maskIssue(_ field: String, _ actual: UInt16, _ expected: UInt16) -> SMECoreSemanticIssue {
        SMECoreSemanticIssue(field: field, actual: "0x\(String(actual, radix: 16))", expected: "0x\(String(expected, radix: 16))")
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

public struct SVEPermMemSemanticIssue: Sendable, Hashable {
    public let field: String
    public let actual: String
    public let expected: String

    public init(field: String, actual: String, expected: String) {
        self.field = field
        self.actual = actual
        self.expected = expected
    }
}

/// Verifies SVE-permute/memory records against the independently-derived
/// semantic model.
public enum SVEPermuteMemorySemanticChecker {
    @_optimize(speed)
    @_effects(readonly)
    public static func verify(draft: Instruction) -> SVEPermMemSemanticIssue? {
        if draft.mnemonic == .undefined { return nil }

        if draft.category != .sve {
            return issue("category", draft.category, Category.sve)
        }
        if draft.branchClass != .none {
            return issue("branchClass", draft.branchClass, BranchClass.none)
        }
        if draft.flagEffect != .none {
            return issue("flagEffect", draft.flagEffect, FlagEffect.none)
        }
        if draft.memoryOrdering != [] {
            return SVEPermMemSemanticIssue(field: "memoryOrdering", actual: "\(draft.memoryOrdering.rawValue)", expected: "0")
        }
        if !draft.scalableEffect.contains(.readsStreamingMode) {
            return SVEPermMemSemanticIssue(field: "readsStreamingMode", actual: "unset", expected: "set")
        }

        let expectedAccess = expectedMemoryAccess(draft.mnemonic)
        if draft.memoryAccess != expectedAccess {
            return issue("memoryAccess", draft.memoryAccess, expectedAccess)
        }

        let family = faultFamily(draft.mnemonic)
        if draft.scalableEffect.contains(.firstFaulting) != (family == .firstFault) {
            return flagIssue("firstFaulting", family == .firstFault)
        }
        if draft.scalableEffect.contains(.nonFaulting) != (family == .nonFault) {
            return flagIssue("nonFaulting", family == .nonFault)
        }
        if draft.scalableEffect.contains(.nonTemporal) != (family == .nonTemporal) {
            return flagIssue("nonTemporal", family == .nonTemporal)
        }

        let touchesFFR = family == .firstFault || family == .nonFault
        if draft.scalableReads.containsFFR != touchesFFR {
            return flagIssue("scalableReads.FFR", touchesFFR)
        }
        if draft.scalableWrites.containsFFR != touchesFFR {
            return flagIssue("scalableWrites.FFR", touchesFFR)
        }

        if draft.scalableEffect.contains(.writesStreamingMode) {
            return flagIssue("writesStreamingMode", false)
        }
        if draft.scalableEffect.contains(.writesZAEnable) {
            return flagIssue("writesZAEnable", false)
        }
        return nil
    }

    /// The expected base memory-access kind for a mnemonic.
    @_effects(readonly)
    public static func expectedMemoryAccess(_ m: Mnemonic) -> MemoryAccess {
        if isLoad(m) { return .load }
        if isStore(m) { return .store }
        if isPrefetch(m) { return .prefetch }
        return .none
    }

    public enum FaultFamily { case normal, firstFault, nonFault, nonTemporal }

    @_effects(readonly)
    public static func faultFamily(_ m: Mnemonic) -> FaultFamily {
        switch m {
        case .ldff1b, .ldff1h, .ldff1w, .ldff1d, .ldff1sb, .ldff1sh, .ldff1sw:
            .firstFault
        case .ldnf1b, .ldnf1h, .ldnf1w, .ldnf1d, .ldnf1sb, .ldnf1sh, .ldnf1sw:
            .nonFault
        case .ldnt1b, .ldnt1h, .ldnt1w, .ldnt1d, .ldnt1sb, .ldnt1sh, .ldnt1sw,
             .stnt1b, .stnt1h, .stnt1w, .stnt1d:
            .nonTemporal
        default:
            .normal
        }
    }

    @_effects(readonly)
    public static func isLoad(_ m: Mnemonic) -> Bool {
        switch m {
        case .ld1b, .ld1h, .ld1w, .ld1d, .ld1sb, .ld1sh, .ld1sw, .ld1q,
             .ldff1b, .ldff1h, .ldff1w, .ldff1d, .ldff1sb, .ldff1sh, .ldff1sw,
             .ldnf1b, .ldnf1h, .ldnf1w, .ldnf1d, .ldnf1sb, .ldnf1sh, .ldnf1sw,
             .ldnt1b, .ldnt1h, .ldnt1w, .ldnt1d, .ldnt1sb, .ldnt1sh, .ldnt1sw,
             .ld1rb, .ld1rh, .ld1rw, .ld1rd, .ld1rsb, .ld1rsh, .ld1rsw,
             .ld1rqb, .ld1rqh, .ld1rqw, .ld1rqd, .ld1rob, .ld1roh, .ld1row, .ld1rod,
             .ld2b, .ld2h, .ld2w, .ld2d, .ld2q, .ld3b, .ld3h, .ld3w, .ld3d, .ld3q,
             .ld4b, .ld4h, .ld4w, .ld4d, .ld4q, .ldr:
            true
        default:
            false
        }
    }

    @_effects(readonly)
    public static func isStore(_ m: Mnemonic) -> Bool {
        switch m {
        case .st1b, .st1h, .st1w, .st1d, .st1q,
             .st2b, .st2h, .st2w, .st2d, .st2q, .st3b, .st3h, .st3w, .st3d, .st3q,
             .st4b, .st4h, .st4w, .st4d, .st4q,
             .stnt1b, .stnt1h, .stnt1w, .stnt1d, .str:
            true
        default:
            false
        }
    }

    @_effects(readonly)
    public static func isPrefetch(_ m: Mnemonic) -> Bool {
        m == .prfb || m == .prfh || m == .prfw || m == .prfd
    }

    @inline(__always)
    public static func issue(_ field: String, _ actual: some RawRepresentable<UInt8>, _ expected: some RawRepresentable<UInt8>) -> SVEPermMemSemanticIssue {
        SVEPermMemSemanticIssue(field: field, actual: "\(actual.rawValue)", expected: "\(expected.rawValue)")
    }

    @inline(__always)
    public static func flagIssue(_ field: String, _ expectedSet: Bool) -> SVEPermMemSemanticIssue {
        SVEPermMemSemanticIssue(field: field, actual: expectedSet ? "unset" : "set", expected: expectedSet ? "set" : "unset")
    }
}

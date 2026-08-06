// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Verify the scalable semantic attributes of one decoded SVE/SME instruction
/// against its region's expected-attribute checker.
public func scalableSemanticIssue(
    for instruction: Instruction,
) -> (field: String, actual: String, expected: String)? {
    let e = instruction.encoding
    switch instruction.category {
    case .sve:
        if isSVEPredicateControlEncoding(e) {
            return SVEPredicateControlSemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        if isSVEIntegerEncoding(e) {
            return SVEIntegerSemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        if isSVEFloatingPointEncoding(e) {
            return SVEFloatingPointSemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        if isSVEPermuteMemoryCryptoEncoding(e) {
            return SVEPermuteMemorySemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        if isSVECounterPredicateEncoding(e) {
            return SME2SemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        return nil
    case .sme:
        if isSMECoreEncoding(e) {
            return SMECoreSemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
        }
        return SME2SemanticChecker.verify(draft: instruction).map { ($0.field, $0.actual, $0.expected) }
    default:
        return nil
    }
}

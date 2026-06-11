// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates PSTATEField — the named PSTATE selectors for the
/// `MSR (immediate)` instruction plus the `.unknown(op1:op2:)`
/// forward-compatibility case.
@Suite("PSTATEField / named cases and unknown round-trip")
struct PSTATEFieldTests {
    @Test func namedCasesAreDistinct() {
        let cases: [PSTATEField] = [.spSel, .daifSet, .daifClr, .uao, .pan, .dit, .tco, .ssbs, .allInt, .pm]
        #expect(Set(cases).count == cases.count)
    }

    @Test func unknownPreservesOp1Op2() {
        let field = PSTATEField.unknown(op1: 5, op2: 3)
        #expect(field == .unknown(op1: 5, op2: 3))
    }

    @Test func twoUnknownsWithSameTupleHashEqual() {
        let a = PSTATEField.unknown(op1: 1, op2: 2)
        let b = PSTATEField.unknown(op1: 1, op2: 2)
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func twoUnknownsWithDifferentTuplesAreDistinct() {
        #expect(PSTATEField.unknown(op1: 1, op2: 2) != PSTATEField.unknown(op1: 1, op2: 3))
        #expect(PSTATEField.unknown(op1: 1, op2: 2) != PSTATEField.unknown(op1: 2, op2: 2))
    }

    @Test func namedCaseDifferentFromUnknown() {
        #expect(PSTATEField.spSel != PSTATEField.unknown(op1: 0, op2: 0))
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One value of each scalable SVE/SME `Operand` case — the
/// complete scalable operand grammar, in declaration order.
///
/// No base-ISA decoder emits any of these, so every existing family
/// canonicalizer must route each one to its "unsupported" sentinel rather
/// than crashing or silently rendering something wrong. The canonicalizer
/// suites sweep this list to prove that.
let everyScalableOperand: [Operand] = [
    .scalableVector(ScalableVectorRef(registerIndex: 0, element: .s)),
    .scalablePredicate(ScalablePredicateRef(registerIndex: 1, qualifier: .merging)),
    .scalableVectorGroup(
        ScalableVectorGroup(firstIndex: 2, count: 2, element: .s, layout: .consecutive),
    ),
    .predicateGroup(firstIndex: 3, count: 2, element: .b),
    .zaTile(index: 0, element: .s),
    .zaTileSlice(
        ZATileSliceOperand(
            tileIndex: 0, element: .s, direction: .horizontal,
            selectRegister: .w(12), offset: 0,
        ),
    ),
    .zaArrayVector(ZAArrayVectorOperand(element: .s, selectRegister: .w(8), offset: 0)),
    .zt0(elementIndex: nil),
    .scalableMemory(ScalableMemoryOperand(base: .gpr(.x(0)))),
    .svePredicatePattern(SVEPredicatePattern(raw: 31)),
    .vectorLengthMultiplier(2),
]

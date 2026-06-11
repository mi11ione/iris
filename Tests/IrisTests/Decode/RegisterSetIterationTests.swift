// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Golden pins for RegisterSet iteration: the lowest-bit-first order,
/// the element policy (bit i → .x(i), bit 31 → sp, bits 32…63 → simd),
/// and the decode-grounded facts that make iteration honest — the zero
/// register is never recorded, bit 31 is SP.
@Suite("RegisterSet / iteration as registers")
struct RegisterSetIterationTests {
    @Test func zeroRegisterParticipationIsNeverRecorded() {
        // CMP x0, x1 discards into xzr: writes iterate empty.
        let cmp = decode(0xEB01_001F)
        #expect(cmp.mnemonic == .cmp)
        #expect(Array(cmp.semanticWrites) == [])
        #expect(Array(cmp.semanticReads) == [.x(0), .x(1)])
        // MOV x0, xzr reads only the zero register: reads iterate empty.
        let mov = decode(0xAA1F_03E0)
        #expect(mov.mnemonic == .mov)
        #expect(Array(mov.semanticReads) == [])
        #expect(Array(mov.semanticWrites) == [.x(0)])
    }

    @Test func bit31IteratesAsStackPointer() {
        // ADD sp, sp, #16 — bit 31 in a RegisterSet unambiguously
        // means SP (proven decoder behavior, not an assumption).
        let add = decode(0x9100_43FF)
        #expect(add.mnemonic == .add)
        #expect(add.semanticReads.contains(.sp()))
        #expect(Array(add.semanticReads) == [.sp()])
        #expect(Array(add.semanticWrites) == [.sp()])
    }

    @Test func simdBitsIterateAsVectorRegisters() {
        // AND v0.8b, v1.8b, v2.8b.
        let and = decode(0x0E22_1C20)
        #expect(and.mnemonic == .and)
        #expect(Array(and.semanticReads) == [.simd(1), .simd(2)])
        #expect(Array(and.semanticWrites) == [.simd(0)])
    }

    @Test func iterationOrderIsLowestCanonicalIndexFirst() {
        let set = RegisterSet(mask: (1 << 0) | (1 << 30) | (1 << 31) | (1 << 32) | (1 << 63))
        #expect(Array(set) == [.x(0), .x(30), .sp(), .simd(0), .simd(31)])
        #expect(set.underestimatedCount == 5)
        #expect(set.map(\.name) == ["x0", "x30", "sp", "v0", "v31"])
    }

    @Test func emptySetIteratesNothing() {
        var iterator = RegisterSet.empty.makeIterator()
        #expect(iterator.next() == nil)
        #expect(RegisterSet.empty.underestimatedCount == 0)
    }
}

/// Validates the RegisterSet algebra — O(1) bit operations mirroring
/// the set vocabulary: subtracting, symmetric difference, removing,
/// subset/superset/disjoint queries, emptiness, and count.
@Suite("RegisterSet / set algebra")
struct RegisterSetAlgebraTests {
    private let a = RegisterSet(mask: 0b0111) //  {x0, x1, x2}
    private let b = RegisterSet(mask: 0b0110) //  {x1, x2}
    private let c = RegisterSet(mask: 0b1000) //  {x3}

    @Test func subtractingRemovesSharedMembers() {
        #expect(a.subtracting(b) == RegisterSet(mask: 0b0001))
        #expect(b.subtracting(a) == .empty)
        #expect(a.subtracting(c) == a)
    }

    @Test func symmetricDifferenceKeepsExclusiveMembers() {
        #expect(a.symmetricDifference(b) == RegisterSet(mask: 0b0001))
        #expect(a.symmetricDifference(a) == .empty)
        #expect(a.symmetricDifference(c) == RegisterSet(mask: 0b1111))
    }

    @Test func removingDropsOneRegister() {
        #expect(a.removing(.x(0)) == b)
        #expect(a.removing(.x(3)) == a)
        // Canonical index >= 64 is ignored, mirroring inserting(_:).
        let synthetic = RegisterRef(canonicalIndex: 80, role: .general, width: .x64)
        #expect(a.removing(synthetic) == a)
        #expect(RegisterSet.empty.inserting(.sp()).removing(.sp()) == .empty)
    }

    @Test func subsetSupersetAndDisjointQueries() {
        #expect(b.isSubset(of: a))
        #expect(!a.isSubset(of: b))
        #expect(a.isSubset(of: a))
        #expect(a.isSuperset(of: b))
        #expect(!b.isSuperset(of: a))
        #expect(a.isDisjoint(with: c))
        #expect(!a.isDisjoint(with: b))
        #expect(RegisterSet.empty.isDisjoint(with: RegisterSet.empty))
    }

    @Test func emptinessAndCount() {
        #expect(RegisterSet.empty.isEmpty)
        #expect(!a.isEmpty)
        #expect(a.count == 3)
        #expect(b.count == 2)
        #expect(RegisterSet.empty.count == 0)
        #expect(RegisterSet(mask: .max).count == 64)
    }
}

/// Validates `RegisterSet`'s `CustomStringConvertible` rendering: a
/// bracketed, ascending, comma-separated list of canonical register
/// names, debug-only and independent of the canonical text path.
@Suite("RegisterSet / description")
struct RegisterSetDescriptionTests {
    @Test func emptySetIsEmptyBrackets() {
        #expect(RegisterSet.empty.description == "[]")
        #expect("\(RegisterSet.empty)" == "[]")
    }

    @Test func singleGPR() {
        #expect(RegisterSet.empty.inserting(.x(5)).description == "[x5]")
    }

    @Test func multipleGPRsAreAscendingAndCommaSeparated() {
        let set = RegisterSet.empty.inserting(.x(30)).inserting(.x(29))
        #expect(set.description == "[x29, x30]")
    }

    @Test func stackPointerRendersAsSp() {
        let set = RegisterSet.empty.inserting(.x(29)).inserting(.x(30)).inserting(.sp())
        #expect(set.description == "[x29, x30, sp]")
    }

    @Test func vectorRegistersRenderAsV() {
        let set = RegisterSet.empty.inserting(.simd(0)).inserting(.simd(31))
        #expect(set.description == "[v0, v31]")
    }

    @Test func mixedGPRSpAndVector() {
        let set = RegisterSet(mask: (1 << 0) | (1 << 31) | (1 << 32))
        #expect(set.description == "[x0, sp, v0]")
    }
}

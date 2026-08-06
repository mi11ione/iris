// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates B / BL.
@Suite("BES / Branch (immediate) decode")
struct BESBranchImmTests {
    @Test func bZeroOffset() {
        let d = decode(0x1400_0000, at: 0x1000)
        #expect(d.mnemonic == .b)
        #expect(d.branchClass == .direct)
        #expect(d.category == .branchesExceptionSystem)
        #expect(Array(d.operands) == [.label(byteOffset: 0)])
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
        #expect(d.flagEffect == .none)
        #expect(d.memoryAccess == .none)
        #expect(d.memoryOrdering == [])
    }

    @Test func bPositiveOffset() {
        let d = decode(0x1400_0001, at: 0)
        #expect(d.mnemonic == .b)
        #expect(Array(d.operands) == [.label(byteOffset: 4)])
    }

    @Test func bNegativeOffset() {
        let d = decode(0x17FF_FFFF, at: 0)
        #expect(d.mnemonic == .b)
        #expect(Array(d.operands) == [.label(byteOffset: -4)])
    }

    @Test func bMaxPositiveOffset() {
        let d = decode(0x15FF_FFFF, at: 0)
        #expect(Array(d.operands) == [.label(byteOffset: 134_217_724)])
    }

    @Test func bMaxNegativeOffset() {
        let d = decode(0x1600_0000, at: 0)
        #expect(Array(d.operands) == [.label(byteOffset: -134_217_728)])
    }

    @Test func blZeroOffset() {
        let d = decode(0x9400_0000, at: 0x1000)
        #expect(d.mnemonic == .bl)
        #expect(d.branchClass == .call)
        #expect(Array(d.operands) == [.label(byteOffset: 0)])
        #expect(d.semanticWrites.contains(.x(30)))
        #expect(d.semanticWrites.mask == (UInt64(1) << 30))
        #expect(d.semanticReads.mask == 0)
    }

    @Test func blPositiveAndNegative() {
        let pos = decode(0x9400_0001, at: 0)
        #expect(Array(pos.operands) == [.label(byteOffset: 4)])
        let neg = decode(0x97FF_FFFF, at: 0)
        #expect(Array(neg.operands) == [.label(byteOffset: -4)])
    }

    @Test func blMaxOffsets() {
        let maxPos = decode(0x95FF_FFFF, at: 0)
        #expect(Array(maxPos.operands) == [.label(byteOffset: 134_217_724)])
        let maxNeg = decode(0x9600_0000, at: 0)
        #expect(Array(maxNeg.operands) == [.label(byteOffset: -134_217_728)])
    }

    @Test func bAtAllBits31to24Values() {
        for top in UInt32(0x14) ... UInt32(0x17) {
            let enc = top << 24
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .b)
        }
        for top in UInt32(0x94) ... UInt32(0x97) {
            let enc = top << 24
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .bl)
        }
    }
}

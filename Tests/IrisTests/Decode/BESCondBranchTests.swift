// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates B.cond / BC.cond decode item 1: bit 4 (`o0`)
/// discriminates — `0` → B.cond emits .bCond, `1` → BC.cond returns
/// .undefined at the v8.7a parity mattr (FEAT_HBC requires v8.8+).
/// Covers every condition code (0..15) plus sign-edge imm19.
@Suite("BES / Conditional branch decode")
struct BESCondBranchTests {
    @Test func bCondEqOffsetZero() {
        // 0x54000000 = b.eq #0
        let d = decode(0x5400_0000, at: 0)
        #expect(d.mnemonic == .bCond)
        #expect(d.branchClass == .conditional)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .conditionCode(.eq))
        #expect(d.operands[1] == .label(byteOffset: 0))
        #expect(d.semanticReads.mask == 0) // NZCV is implicit, not modeled
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func bCondAllConditions() {
        // Every 4-bit cond value 0..15 must decode to a valid B.cond.
        let cases: [(UInt32, ConditionCode)] = [
            (0x5400_0000, .eq), (0x5400_0001, .ne),
            (0x5400_0002, .cs), (0x5400_0003, .cc),
            (0x5400_0004, .mi), (0x5400_0005, .pl),
            (0x5400_0006, .vs), (0x5400_0007, .vc),
            (0x5400_0008, .hi), (0x5400_0009, .ls),
            (0x5400_000A, .ge), (0x5400_000B, .lt),
            (0x5400_000C, .gt), (0x5400_000D, .le),
            (0x5400_000E, .al), (0x5400_000F, .nv),
        ]
        for (enc, expected) in cases {
            let d = decode(enc, at: 0)
            #expect(d.mnemonic == .bCond, "encoding \(String(enc, radix: 16))")
            #expect(d.operands[0] == .conditionCode(expected))
        }
    }

    @Test func bcCondDecodes() {
        // Bit 4 = 1 → BC.cond (FEAT_HBC) — valid at the maximal feature set.
        let d = decode(0x5400_0010, at: 0)
        #expect(d.mnemonic == .bcCond)
        #expect(d.category == .branchesExceptionSystem)
        #expect(d.branchClass == .conditional)
    }

    @Test func bCondImm19PositiveOffset() {
        // imm19 = 1, cond = 0 → byteOffset = 4
        // bits 23:5 = 0x1 << 5 = 0x20 → encoding = 0x54000020
        let d = decode(0x5400_0020, at: 0)
        #expect(d.operands[1] == .label(byteOffset: 4))
    }

    @Test func bCondImm19NegativeOffset() {
        // imm19 = -1 (all 19 bits set) → byteOffset = -4
        // bits 23:5 = 0x7FFFF << 5 = 0xFFFFE0 → encoding = 0x54FFFFE0
        let d = decode(0x54FF_FFE0, at: 0)
        #expect(d.operands[1] == .label(byteOffset: -4))
    }

    @Test func bCondImm19MaxPositiveOffset() {
        // imm19 = 0x3FFFF → byteOffset = 1048572
        let d = decode(0x547F_FFE0, at: 0)
        #expect(d.operands[1] == .label(byteOffset: 1_048_572))
    }

    @Test func bCondImm19MaxNegativeOffset() {
        // imm19 = 0x40000 → byteOffset = -1048576
        let d = decode(0x5480_0000, at: 0)
        #expect(d.operands[1] == .label(byteOffset: -1_048_576))
    }

    @Test func universalFields() {
        let d = decode(0x5400_0000, at: 0)
        #expect(d.memoryAccess == .none)
        #expect(d.memoryOrdering == [])
        #expect(d.flagEffect == .readsNZCV)
        #expect(d.category == .branchesExceptionSystem)
    }
}

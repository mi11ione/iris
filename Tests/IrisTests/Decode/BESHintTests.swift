// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates HINT decode — the HintTable named-imm7 algorithm.
/// Every named imm7 (0..31, BTI sub-targets at 32/34/36/38) maps to a
/// dedicated mnemonic; unrecognized imm7 falls back to `.hint` +
/// `.unsignedImmediate(value:, width: 7)`. BTI sub-target 1/2/3 carries
/// a 2-bit immediate operand (none/c/j/jc). Reserved future-feature
/// slots (19 GCSB, 22 CLRBHB, 40 CHKFEAT) emit `.hint` at v8.7a mattr.
@Suite("BES / HINT decode (imm7 = 0..127)")
struct BESHintTests {
    /// Helper: build the HINT encoding for a given imm7 (bits 11:5).
    private func enc(_ imm7: UInt8) -> UInt32 {
        // bits 31:22 = 1101010100, bit 21 = 0, bits 20:12 = 000110010,
        // bits 11:5 = imm7, bits 4:0 = 11111
        UInt32(0xD503_201F) | (UInt32(imm7) << 5)
    }

    @Test func hint0IsNop() {
        let d = decode(enc(0), at: 0)
        #expect(d.mnemonic == .nop)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func hint1IsYield() {
        #expect(decode(enc(1), at: 0).mnemonic == .yield)
    }

    @Test func eventWaitsAndSendings() {
        #expect(decode(enc(2), at: 0).mnemonic == .wfe)
        #expect(decode(enc(3), at: 0).mnemonic == .wfi)
        #expect(decode(enc(4), at: 0).mnemonic == .sev)
        #expect(decode(enc(5), at: 0).mnemonic == .sevl)
    }

    @Test func dghAndXpaclri() {
        #expect(decode(enc(6), at: 0).mnemonic == .dgh)
        #expect(decode(enc(7), at: 0).mnemonic == .xpaclri)
    }

    @Test func pac1716Variants() {
        // HINT 8/10/12/14 = pacia1716/pacib1716/autia1716/autib1716
        #expect(decode(enc(8), at: 0).mnemonic == .pacia1716)
        #expect(decode(enc(10), at: 0).mnemonic == .pacib1716)
        #expect(decode(enc(12), at: 0).mnemonic == .autia1716)
        #expect(decode(enc(14), at: 0).mnemonic == .autib1716)
    }

    @Test func pac1716OddSlotsAreHint() {
        // HINT 9/11/13/15 are reserved (odd op2 in the 1716 block) → .hint
        for n: UInt8 in [9, 11, 13, 15] {
            let d = decode(enc(n), at: 0)
            #expect(d.mnemonic == .hint)
            #expect(Array(d.operands) == [.unsignedImmediate(value: UInt64(n), width: 7)])
        }
    }

    @Test func syncHints() {
        #expect(decode(enc(16), at: 0).mnemonic == .esb)
        #expect(decode(enc(17), at: 0).mnemonic == .psb)
        #expect(decode(enc(18), at: 0).mnemonic == .tsb)
        #expect(decode(enc(20), at: 0).mnemonic == .csdb)
    }

    @Test func gcsbHint19IsNamed() {
        // GCSB DSYNC (HINT 19) — named at the maximal feature set (+gcs).
        let d = decode(enc(19), at: 0)
        #expect(d.mnemonic == .gcsbDsync)
    }

    @Test func clrbhbHint22IsNamed() {
        // CLRBHB (HINT 22) — named at the maximal feature set (+clrbhb).
        let d = decode(enc(22), at: 0)
        #expect(d.mnemonic == .clrbhb)
    }

    @Test func chkfeatHint40IsNamed() {
        // CHKFEAT (HINT 40) — named at the maximal feature set (+chk).
        let d = decode(enc(40), at: 0)
        #expect(d.mnemonic == .chkfeat)
    }

    @Test func pacZSpVariants() {
        // HINT 24..31 = PAC Z/SP variants per corpus mapping.
        let pacZspMap: [(UInt8, Mnemonic)] = [
            (24, .paciaz), (25, .paciasp),
            (26, .pacibz), (27, .pacibsp),
            (28, .autiaz), (29, .autiasp),
            (30, .autibz), (31, .autibsp),
        ]
        for (imm7, expected) in pacZspMap {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic == expected, "HINT \(imm7)")
        }
    }

    @Test func btiBareNoSubTarget() {
        // HINT 32 = bare BTI (no sub-target).
        let d = decode(enc(32), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(d.operands.isEmpty)
    }

    @Test func btiCSubTarget() {
        // HINT 34 = BTI c (sub-target 1)
        let d = decode(enc(34), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 1, width: 2)])
    }

    @Test func btiJSubTarget() {
        // HINT 36 = BTI j (sub-target 2)
        let d = decode(enc(36), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 2, width: 2)])
    }

    @Test func btiJcSubTarget() {
        // HINT 38 = BTI jc (sub-target 3)
        let d = decode(enc(38), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 3, width: 2)])
    }

    @Test func btiOddSlotsAreHint() {
        // HINT 33/35/37/39 in BTI block are reserved → .hint
        for n: UInt8 in [33, 35, 37, 39] {
            let d = decode(enc(n), at: 0)
            #expect(d.mnemonic == .hint)
        }
    }

    @Test func reservedHint64IsGenericHint() {
        let d = decode(enc(64), at: 0)
        #expect(d.mnemonic == .hint)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 64, width: 7)])
    }

    @Test func reservedHint127IsGenericHint() {
        let d = decode(enc(127), at: 0)
        #expect(d.mnemonic == .hint)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 127, width: 7)])
    }

    @Test func everyImm7Decodes() {
        // Exhaustive coverage: every imm7 ∈ 0..127 produces a record
        // (never .undefined). This proves the 128-entry HintTable is
        // fully populated.
        for imm7: UInt8 in 0 ..< 128 {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic != .undefined, "HINT \(imm7)")
            #expect(d.category == .branchesExceptionSystem)
        }
    }
}

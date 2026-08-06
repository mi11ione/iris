// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates HINT decode.
@Suite("BES / HINT decode (imm7 = 0..127)")
struct BESHintTests {
    private func enc(_ imm7: UInt8) -> UInt32 {
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
        #expect(decode(enc(8), at: 0).mnemonic == .pacia1716)
        #expect(decode(enc(10), at: 0).mnemonic == .pacib1716)
        #expect(decode(enc(12), at: 0).mnemonic == .autia1716)
        #expect(decode(enc(14), at: 0).mnemonic == .autib1716)
    }

    @Test func pac1716OddSlotsAreHint() {
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
        let d = decode(enc(19), at: 0)
        #expect(d.mnemonic == .gcsbDsync)
    }

    @Test func clrbhbHint22IsNamed() {
        let d = decode(enc(22), at: 0)
        #expect(d.mnemonic == .clrbhb)
    }

    @Test func chkfeatHint40IsNamed() {
        let d = decode(enc(40), at: 0)
        #expect(d.mnemonic == .chkfeat)
    }

    @Test func pacZSpVariants() {
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

    @Test func pacHintSpaceImplicitRegisterSets() {
        let x16: UInt64 = 1 << 16
        let x17: UInt64 = 1 << 17
        let x30: UInt64 = 1 << 30
        let sp: UInt64 = 1 << 31
        let cases: [(UInt8, Mnemonic, UInt64, UInt64)] = [
            (25, .paciasp, x30 | sp, x30), (27, .pacibsp, x30 | sp, x30),
            (29, .autiasp, x30 | sp, x30), (31, .autibsp, x30 | sp, x30),
            (24, .paciaz, x30, x30), (26, .pacibz, x30, x30),
            (28, .autiaz, x30, x30), (30, .autibz, x30, x30),
            (8, .pacia1716, x16 | x17, x17), (10, .pacib1716, x16 | x17, x17),
            (12, .autia1716, x16 | x17, x17), (14, .autib1716, x16 | x17, x17),
            (7, .xpaclri, x30, x30),
        ]
        for (imm7, expected, reads, writes) in cases {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic == expected, "HINT \(imm7)")
            #expect(d.semanticReads.mask == reads,
                    "\(expected.name) reads 0x\(String(d.semanticReads.mask, radix: 16)) expected 0x\(String(reads, radix: 16))")
            #expect(d.semanticWrites.mask == writes,
                    "\(expected.name) writes 0x\(String(d.semanticWrites.mask, radix: 16)) expected 0x\(String(writes, radix: 16))")
        }
    }

    @Test func nonPacHintSpaceSlotsHaveNoRegisterEffects() {
        for imm7: UInt8 in [0, 1, 2, 3, 4, 5, 6, 16, 17, 18, 19, 20, 22, 32, 34, 40, 64, 127] {
            let d = decode(enc(imm7), at: 0)
            #expect(d.semanticReads.mask == 0, "HINT \(imm7) reads")
            #expect(d.semanticWrites.mask == 0, "HINT \(imm7) writes")
        }
    }

    @Test func btiBareNoSubTarget() {
        let d = decode(enc(32), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 0, width: 2)])
    }

    @Test func btiCSubTarget() {
        let d = decode(enc(34), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 1, width: 2)])
    }

    @Test func btiJSubTarget() {
        let d = decode(enc(36), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 2, width: 2)])
    }

    @Test func btiJcSubTarget() {
        let d = decode(enc(38), at: 0)
        #expect(d.mnemonic == .bti)
        #expect(Array(d.operands) == [.unsignedImmediate(value: 3, width: 2)])
    }

    @Test func btiOddSlotsAreHint() {
        for n: UInt8 in [33, 35, 37, 41] {
            let d = decode(enc(n), at: 0)
            #expect(d.mnemonic == .hint)
        }
    }

    @Test func storeSharingAndCoherencyHints() {
        #expect(decode(enc(39), at: 0).mnemonic == .pacm)
        #expect(decode(enc(52), at: 0).mnemonic == .stcph)
        #expect(Array(decode(enc(48), at: 0).operands) == [.unsignedImmediate(value: 0, width: 3)])
        #expect(Array(decode(enc(51), at: 0).operands) == [.unsignedImmediate(value: 1, width: 3)])
        #expect(decode(enc(50), at: 0).mnemonic == .shuh)
        #expect(Array(decode(enc(55), at: 0).operands) == [.unsignedImmediate(value: 7, width: 3)])
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
        for imm7: UInt8 in 0 ..< 128 {
            let d = decode(enc(imm7), at: 0)
            #expect(d.mnemonic != .undefined, "HINT \(imm7)")
            #expect(d.category == .branchesExceptionSystem)
        }
    }
}

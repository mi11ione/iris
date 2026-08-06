// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Golden table for `Instruction.branchTarget`.
@Suite("Instruction / branchTarget golden table")
struct BranchTargetGoldenTests {
    @Test func directAndConditionalTransfersResolveAbsoluteTargets() {
        let rows: [(word: UInt32, at: UInt64, mnemonic: Mnemonic, target: UInt64)] = [
            (0x1400_0002, 0x1000, .b, 0x1008),
            (0x17FF_FFFF, 0x1000, .b, 0x0FFC),
            (0x9400_0001, 0x4000, .bl, 0x4004),
            (0x5400_0080, 0x2000, .bCond, 0x2010),
            (0x5400_0090, 0x2000, .bcCond, 0x2010),
            (0xB400_0040, 0x0000, .cbz, 0x0008),
            (0x3500_0021, 0x0100, .cbnz, 0x0104),
            (0x3600_0040, 0x0000, .tbz, 0x0008),
            (0x3700_0041, 0x0000, .tbnz, 0x0008),
        ]
        for row in rows {
            let instruction = decode(row.word, at: row.at)
            #expect(instruction.mnemonic == row.mnemonic,
                    "0x\(String(row.word, radix: 16)) decoded \(instruction.mnemonic.name)")
            #expect(instruction.branchTarget == row.target,
                    "0x\(String(row.word, radix: 16)) target \(String(describing: instruction.branchTarget))")
            #expect(instruction.pcRelativeTarget == nil)
        }
    }

    @Test func indirectReturnAndExceptionControlFlowIsNil() {
        let rows: [(word: UInt32, mnemonic: Mnemonic, branchClass: BranchClass)] = [
            (0xD61F_0000, .br, .indirect),
            (0xD63F_0000, .blr, .call),
            (0xD65F_03C0, .ret, .return),
            (0xD65F_0BFF, .retaa, .return),
            (0xD400_0021, .svc, .exception),
            (0xD420_0000, .brk, .exception),
        ]
        for row in rows {
            let instruction = decode(row.word, at: 0x1000)
            #expect(instruction.mnemonic == row.mnemonic)
            #expect(instruction.branchClass == row.branchClass)
            #expect(instruction.branchTarget == nil,
                    "\(row.mnemonic.name) must not resolve a target")
        }
        #expect(decode(0xD503_201F).branchTarget == nil)
        #expect(decode(0x9100_0400).branchTarget == nil)
    }

    @Test func targetArithmeticIsModulo2To64() {
        let nearTop = UInt64.max - 3
        let b = decode(0x1400_0002, at: nearTop)
        #expect(b.branchTarget == 4)
        let backwards = decode(0x17FF_FFFF, at: 0)
        #expect(backwards.branchTarget == UInt64.max - 3)
    }
}

/// Golden table for `Instruction.pcRelativeTarget`.
@Suite("Instruction / pcRelativeTarget golden table")
struct PCRelativeTargetGoldenTests {
    @Test func adrResolvesByteOffsets() {
        let adr = decode(0x1000_0080, at: 0x1000)
        #expect(adr.mnemonic == .adr)
        #expect(adr.pcRelativeTarget == 0x1010)
        #expect(adr.branchTarget == nil)
    }

    @Test func adrpResolvesPageMath() {
        let adrp = decode(0xB000_0000, at: 0x1234)
        #expect(adrp.mnemonic == .adrp)
        #expect(adrp.pcRelativeTarget == 0x2000)
        #expect(decode(0xB000_0000, at: 0x1000).pcRelativeTarget == 0x2000)
        #expect(adrp.branchTarget == nil)
    }

    @Test func pcLiteralLoadsResolveDisplacements() {
        let rows: [(word: UInt32, at: UInt64, mnemonic: Mnemonic, target: UInt64)] = [
            (0x1800_0040, 0x0000, .ldr, 0x0008),
            (0x5800_0040, 0x0100, .ldr, 0x0108),
            (0x58FF_FFC0, 0x1000, .ldr, 0x0FF8),
            (0x9800_0040, 0x0000, .ldrsw, 0x0008),
            (0xD800_0040, 0x0000, .prfm, 0x0008),
        ]
        for row in rows {
            let instruction = decode(row.word, at: row.at)
            #expect(instruction.mnemonic == row.mnemonic,
                    "0x\(String(row.word, radix: 16)) decoded \(instruction.mnemonic.name)")
            #expect(instruction.pcRelativeTarget == row.target,
                    "0x\(String(row.word, radix: 16)) target \(String(describing: instruction.pcRelativeTarget))")
            #expect(instruction.branchTarget == nil)
        }
    }

    @Test func nonPCRelativeInstructionsAreNil() {
        #expect(decode(0xF940_0021).pcRelativeTarget == nil)
        #expect(decode(0x9100_0400).pcRelativeTarget == nil)
        #expect(decode(0x1400_0002).pcRelativeTarget == nil)
        #expect(decode(0xD503_201F).pcRelativeTarget == nil)
    }
}

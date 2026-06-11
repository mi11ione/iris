// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Golden table for `Instruction.branchTarget`, covering the whole
/// documented contract: direct/conditional/call transfers resolve to
/// computed absolute targets; indirect, return, and exception-generating
/// control flow is nil; modular (wrapping) target arithmetic composes
/// with the address model.
@Suite("Instruction / branchTarget golden table")
struct BranchTargetGoldenTests {
    @Test func directAndConditionalTransfersResolveAbsoluteTargets() {
        // (word, decode address, expected mnemonic, expected target)
        let rows: [(word: UInt32, at: UInt64, mnemonic: Mnemonic, target: UInt64)] = [
            (0x1400_0002, 0x1000, .b, 0x1008), //       b   +8
            (0x17FF_FFFF, 0x1000, .b, 0x0FFC), //       b   -4
            (0x9400_0001, 0x4000, .bl, 0x4004), //      bl  +4
            (0x5400_0080, 0x2000, .bCond, 0x2010), //   b.eq +16
            (0x5400_0090, 0x2000, .bcCond, 0x2010), //  bc.eq +16
            (0xB400_0040, 0x0000, .cbz, 0x0008), //     cbz x0, +8
            (0x3500_0021, 0x0100, .cbnz, 0x0104), //    cbnz w1, +4
            (0x3600_0040, 0x0000, .tbz, 0x0008), //     tbz w0, #0, +8
            (0x3700_0041, 0x0000, .tbnz, 0x0008), //    tbnz w1, #0, +8
        ]
        for row in rows {
            let instruction = decode(row.word, at: row.at)
            #expect(instruction.mnemonic == row.mnemonic,
                    "0x\(String(row.word, radix: 16)) decoded \(instruction.mnemonic.name)")
            #expect(instruction.branchTarget == row.target,
                    "0x\(String(row.word, radix: 16)) target \(String(describing: instruction.branchTarget))")
            // branchTarget and pcRelativeTarget are disjoint.
            #expect(instruction.pcRelativeTarget == nil)
        }
    }

    @Test func indirectReturnAndExceptionControlFlowIsNil() {
        // (word, expected mnemonic, expected branchClass)
        let rows: [(word: UInt32, mnemonic: Mnemonic, branchClass: BranchClass)] = [
            (0xD61F_0000, .br, .indirect), //   br x0 — register-valued
            (0xD63F_0000, .blr, .call), //      blr x0 — call, indirect
            (0xD65F_03C0, .ret, .return), //    ret
            (0xD65F_0BFF, .retaa, .return), //  retaa
            (0xD400_0021, .svc, .exception), // svc #1 — vectored
            (0xD420_0000, .brk, .exception), // brk #0
        ]
        for row in rows {
            let instruction = decode(row.word, at: 0x1000)
            #expect(instruction.mnemonic == row.mnemonic)
            #expect(instruction.branchClass == row.branchClass)
            #expect(instruction.branchTarget == nil,
                    "\(row.mnemonic.name) must not resolve a target")
        }
        // Non-branches are nil through the branchClass gate.
        #expect(decode(0xD503_201F).branchTarget == nil) // nop
        #expect(decode(0x9100_0400).branchTarget == nil) // add
    }

    @Test func targetArithmeticIsModulo2To64() {
        // The wrap composition case: a branch whose target crosses 2^64
        // wraps, matching the stream's address model.
        let nearTop = UInt64.max - 3
        let b = decode(0x1400_0002, at: nearTop) // b +8
        #expect(b.branchTarget == 4)
        let backwards = decode(0x17FF_FFFF, at: 0) // b -4
        #expect(backwards.branchTarget == UInt64.max - 3)
    }
}

/// Golden table for `Instruction.pcRelativeTarget`: ADR offset math,
/// ADRP page math (inside the library, never caller arithmetic), and
/// the PC-literal load/prefetch family; everything else nil.
@Suite("Instruction / pcRelativeTarget golden table")
struct PCRelativeTargetGoldenTests {
    @Test func adrResolvesByteOffsets() {
        let adr = decode(0x1000_0080, at: 0x1000) // adr x0, #16
        #expect(adr.mnemonic == .adr)
        #expect(adr.pcRelativeTarget == 0x1010)
        #expect(adr.branchTarget == nil)
    }

    @Test func adrpResolvesPageMath() {
        // adrp x0, #+1 page from a mid-page address: the target is the
        // CURRENT page base plus the page offset — the &~0xFFF masking
        // is the library's job.
        let adrp = decode(0xB000_0000, at: 0x1234)
        #expect(adrp.mnemonic == .adrp)
        #expect(adrp.pcRelativeTarget == 0x2000)
        // From a page-aligned address the mask is a no-op.
        #expect(decode(0xB000_0000, at: 0x1000).pcRelativeTarget == 0x2000)
        #expect(adrp.branchTarget == nil)
    }

    @Test func pcLiteralLoadsResolveDisplacements() {
        // (word, decode address, expected mnemonic, expected target)
        let rows: [(word: UInt32, at: UInt64, mnemonic: Mnemonic, target: UInt64)] = [
            (0x1800_0040, 0x0000, .ldr, 0x0008), //   ldr w0, #8
            (0x5800_0040, 0x0100, .ldr, 0x0108), //   ldr x0, #8
            (0x58FF_FFC0, 0x1000, .ldr, 0x0FF8), //   ldr x0, #-8
            (0x9800_0040, 0x0000, .ldrsw, 0x0008), // ldrsw x0, #8
            (0xD800_0040, 0x0000, .prfm, 0x0008), //  prfm plil1keep-class, #8
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
        #expect(decode(0xF940_0021).pcRelativeTarget == nil) // ldr x1, [x1]
        #expect(decode(0x9100_0400).pcRelativeTarget == nil) // add
        #expect(decode(0x1400_0002).pcRelativeTarget == nil) // b (label is control flow)
        #expect(decode(0xD503_201F).pcRelativeTarget == nil) // nop
    }
}

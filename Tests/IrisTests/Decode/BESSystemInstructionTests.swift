// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates SYS / SYSL decode. The decoder emits the
/// `.sys`/`.sysl` mnemonic + a single `.systemOp(SystemOp(rawEncoding:))`
/// operand preserving the entire 32-bit word. Semantic reads for SYS
/// are gated by whether the matched alias touches Rt (aliases that
/// don't take Rt encode it as XZR; we don't read XZR). Generic SYS
/// without a matching alias falls back to Rt != 31 heuristic.
@Suite("BES / SYS / SYSL decode")
struct BESSystemInstructionTests {
    @Test func icIalluiseNoRt() {
        // SYS #0, C7, C1, #0 → IC IALLUIS (no Rt)
        // Encoding: bits 31:22 = 1101010100, bit 21 = 0, bits 20:19 = 01,
        //   op1=000, CRn=0111, CRm=0001, op2=000, Rt=11111
        // = 0xD508_711F
        let d = decode(0xD508_711F, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .systemOp(SystemOp(rawEncoding: 0xD508_711F)))
        // IC IALLUIS has needsReg=false → no Rt in reads.
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func dcCvacWithRt() {
        // DC CVAC, X5 → op1=011, CRn=0111, CRm=1010, op2=001, Rt=5
        // Encoding: 0xD50B7A25
        let d = decode(0xD50B_7A25, at: 0)
        #expect(d.mnemonic == .sys)
        // needsReg=true → reads Rt.
        #expect(d.semanticReads.contains(.x(5)))
    }

    @Test func tlbiVae1Is() {
        // TLBI VAE1IS, X1 — op1=000, CRn=1000, CRm=0011, op2=001, Rt=1
        // Encoding: 0xD508_8321
        let d = decode(0xD508_8321, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func tlbiVmalle1NoRtReadEvenWithSettableRt() {
        // TLBI VMALLE1 — needsReg=false. Even if Rt encodes X5, the
        // alias doesn't read it → semanticReads should be empty.
        // Encoding: op1=000, CRn=1000, CRm=0111, op2=000, Rt=5 → 0xD508_8705
        let d = decode(0xD508_8705, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.mask == 0) // alias.needsReg = false
    }

    @Test func genericSysWithoutAliasReadsRtWhenNotZr() {
        // Unknown (op1=001, CRn=0010, CRm=0011, op2=100), Rt=0 → reads X0
        // Encoding: 0xD509_2380
        let d = decode(0xD509_2380, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.contains(.x(0)))
    }

    @Test func genericSysWithRtZrDoesNotRead() {
        // Unknown alias with Rt = 31 → doesn't read XZR (heuristic).
        // Encoding: 0xD509_239F
        let d = decode(0xD509_239F, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func syslWritesRtNotReads() {
        // SYSL with L=1, Rt=0 → writes X0.
        // Encoding: bits 21=1, bits 20:19=01, op1=011, CRn=0111, CRm=1100, op2=001, Rt=0
        // = 0xD52B_7C20
        let d = decode(0xD52B_7C20, at: 0)
        #expect(d.mnemonic == .sysl)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func syslOperandIsSystemOp() {
        let d = decode(0xD52B_7C20, at: 0)
        #expect(d.operands[0] == .systemOp(SystemOp(rawEncoding: 0xD52B_7C20)))
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates SYS / SYSL.
@Suite("BES / SYS / SYSL decode")
struct BESSystemInstructionTests {
    @Test func icIalluiseNoRt() {
        let d = decode(0xD508_711F, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.operands.count == 1)
        #expect(d.operands[0] == .systemOp(SystemOp(rawEncoding: 0xD508_711F)))
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func dcCvacWithRt() {
        let d = decode(0xD50B_7A25, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.contains(.x(5)))
    }

    @Test func tlbiVae1Is() {
        let d = decode(0xD508_8321, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.contains(.x(1)))
    }

    @Test func tlbiVmalle1NoRtReadEvenWithSettableRt() {
        let d = decode(0xD508_8705, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func genericSysWithoutAliasReadsRtWhenNotZr() {
        let d = decode(0xD509_2380, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.contains(.x(0)))
    }

    @Test func genericSysWithRtZrDoesNotRead() {
        let d = decode(0xD509_239F, at: 0)
        #expect(d.mnemonic == .sys)
        #expect(d.semanticReads.mask == 0)
    }

    @Test func syslWritesRtNotReads() {
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

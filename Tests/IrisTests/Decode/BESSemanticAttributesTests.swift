// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates `BESSemanticChecker.verify(draft:)` + `BESSemanticAttributes`
/// Drives the checker through every kind of BES record
/// — direct/call/indirect/return/conditional/exception/none branch
/// classes — to confirm the checker accepts each correctly-formed
/// record AND rejects deliberately-mutated drafts with the expected
/// `BESSemanticIssue.field` discriminator.
@Suite("BES / Semantic attributes + checker")
struct BESSemanticAttributesTests {
    @Test func expectedBranchClassDirect() {
        #expect(BESSemanticAttributes.expectedBranchClass(for: .b) == .direct)
    }

    @Test func expectedBranchClassCallFamily() {
        #expect(BESSemanticAttributes.expectedBranchClass(for: .bl) == .call)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .blr) == .call)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .blraa) == .call)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .blrab) == .call)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .blraaz) == .call)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .blrabz) == .call)
    }

    @Test func expectedBranchClassIndirectFamily() {
        for m: Mnemonic in [.br, .braa, .brab, .braaz, .brabz] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .indirect)
        }
    }

    @Test func expectedBranchClassReturnFamily() {
        for m: Mnemonic in [.ret, .retaa, .retab, .eret, .eretaa, .eretab, .drps] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .return)
        }
    }

    @Test func expectedBranchClassConditionalFamily() {
        for m: Mnemonic in [.bCond, .bcCond, .cbz, .cbnz, .tbz, .tbnz] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .conditional)
        }
    }

    @Test func expectedBranchClassExceptionFamily() {
        for m: Mnemonic in [.svc, .hvc, .smc, .brk, .hlt, .dcps1, .dcps2, .dcps3] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .exception)
        }
    }

    @Test func expectedBranchClassNoneForNonBranches() {
        for m: Mnemonic in [.nop, .dsb, .msr, .mrs, .cfinv, .wfet, .sys] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .none)
        }
    }

    @Test func expectedBranchClassUDFIsException() {
        // UDF is dispatcher-owned (op0=0 reserved tier) but routes to BES;
        // it generates an Undefined Instruction exception — same class as
        // BRK/HLT. The decode record carried .exception from the start
        // (UDFDecodeTests); this pins the checker table's agreement
        // (formerly the catalogued `udf-checker-branchclass` defect).
        #expect(BESSemanticAttributes.expectedBranchClass(for: .udf) == .exception)
        #expect(BESSemanticChecker.verify(decode(0x0000_0000, at: 0)) == nil)
        #expect(BESSemanticChecker.verify(decode(0x0000_ABCD, at: 0)) == nil)
    }

    @Test func verifyAcceptsValidNop() {
        let d = decode(0xD503_201F, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidB() {
        let d = decode(0x1400_0000, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidBl() {
        let d = decode(0x9400_0000, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidRetLr() {
        let d = decode(0xD65F_03C0, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidBraa() {
        let d = decode(0xD71F_0A11, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidRetaa() {
        let d = decode(0xD65F_0BFF, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidBcond() {
        let d = decode(0x5400_0000, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidSvc() {
        let d = decode(0xD400_0001, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidMsrSpSel() {
        let d = decode(0xD500_40BF, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidMrs() {
        let d = decode(0xD53B_D040, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidSys() {
        let d = decode(0xD508_711F, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsValidWfet() {
        let d = decode(0xD503_1000, at: 0)
        #expect(BESSemanticChecker.verify(d) == nil)
    }

    @Test func verifyAcceptsUndefined() {
        // Undefined records are skipped — always nil regardless of state.
        let undef = Instruction(address: 0, encoding: 0xFFFF_FFFF, mnemonic: .undefined, category: .undefined)
        #expect(BESSemanticChecker.verify(undef) == nil)
    }

    @Test func verifyRejectsWrongMemoryAccess() {
        let d = mutated(decode(0x1400_0000, at: 0), memoryAccess: .load)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "memoryAccess")
    }

    @Test func verifyRejectsWrongMemoryOrdering() {
        let d = mutated(decode(0x1400_0000, at: 0), memoryOrdering: .acquire)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "memoryOrdering")
    }

    @Test func verifyRejectsWrongFlagEffect() {
        let d = mutated(decode(0x1400_0000, at: 0), flagEffect: .nzcv)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "flagEffect")
    }

    @Test func verifyRejectsWrongCategory() {
        let d = mutated(decode(0x1400_0000, at: 0), category: .dataProcessingImmediate)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "category")
    }

    @Test func verifyRejectsWrongBranchClass() {
        // B should be .direct.
        let d = mutated(decode(0x1400_0000, at: 0), branchClass: .indirect)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "branchClass")
    }

    @Test func verifyRejectsExtraneousSemanticReads() {
        // B has empty reads expected — adding X5 should fail.
        let d = mutated(decode(0x1400_0000, at: 0), semanticReads: .empty.inserting(.x(5)))
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func verifyRejectsMissingSemanticReads() {
        // BR X0 requires Rn (X0) in reads — empty it.
        let d = mutated(decode(0xD61F_0000, at: 0), semanticReads: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func verifyRejectsWrongSemanticWrites() {
        // BL must write X30 — wipe it.
        let d = mutated(decode(0x9400_0000, at: 0), semanticWrites: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }

    @Test func firstRegisterMaskFromOperandList() {
        let ops: [Operand] = [.unsignedImmediate(value: 1, width: 4), .register(.x(5)), .register(.x(7))]
        #expect(BESSemanticAttributes.firstRegisterMask(ops) == (UInt64(1) << 5))
    }

    @Test func firstRegisterMaskAbsent() {
        let ops: [Operand] = [.unsignedImmediate(value: 1, width: 4)]
        #expect(BESSemanticAttributes.firstRegisterMask(ops) == nil)
    }

    @Test func lastRegisterMaskFromOperandList() {
        let ops: [Operand] = [.register(.x(3)), .unsignedImmediate(value: 1, width: 4), .register(.x(9))]
        #expect(BESSemanticAttributes.lastRegisterMask(ops) == (UInt64(1) << 9))
    }

    @Test func lastRegisterMaskAbsent() {
        #expect(BESSemanticAttributes.lastRegisterMask([]) == nil)
    }

    @Test func firstTwoRegistersMask() {
        let ops: [Operand] = [.register(.x(2)), .register(.x(5)), .register(.x(7))]
        let mask = BESSemanticAttributes.firstTwoRegistersMask(ops)
        #expect(mask == ((UInt64(1) << 2) | (UInt64(1) << 5)))
    }

    @Test func firstTwoRegistersMaskWithOnlyOne() {
        let ops: [Operand] = [.register(.x(2)), .unsignedImmediate(value: 1, width: 4)]
        let mask = BESSemanticAttributes.firstTwoRegistersMask(ops)
        #expect(mask == (UInt64(1) << 2))
    }

    @Test func firstTwoRegistersMaskEmpty() {
        #expect(BESSemanticAttributes.firstTwoRegistersMask([]) == 0)
    }

    @Test func expectedReadMaskBHasEmpty() {
        let d = decode(0x1400_0000, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedReadMaskBraaCoversBothRegisters() {
        let d = decode(0xD71F_0A11, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == ((UInt64(1) << 16) | (UInt64(1) << 17)))
    }

    @Test func expectedReadMaskRetaaIsLrAndSp() {
        let d = decode(0xD65F_0BFF, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        let lrBit = UInt64(1) << 30
        let spBit = UInt64(1) << 31
        #expect(r?.required == (lrBit | spBit))
    }

    @Test func expectedReadMaskSysNoRegAliasIsEmpty() {
        // IC IALLUIS takes no register (needsReg = false) — expected reads = {}.
        // The checker mirrors the alias-table gating rather than deferring
        // to whatever the decoder produced.
        let d = decode(0xD508_711F, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedReadMaskSysWithRegAliasIsRt() {
        // DC CVAC, X5 — needsReg = true; expected reads = {X5}.
        let d = decode(0xD50B_7A25, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        let x5Bit = UInt64(1) << 5
        #expect(r?.required == x5Bit)
        #expect(r?.allowed == x5Bit)
    }

    @Test func expectedReadMaskSysUnknownAliasFallback() {
        // Unknown SYS encoding with Rt != 31 → readsRt heuristic.
        let d = decode(0xD509_2380, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 1) // Rt = 0
    }

    @Test func expectedReadMaskSysUnknownAliasRtZrNoRead() {
        // Unknown SYS with Rt = 31 → no read.
        let d = decode(0xD509_239F, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
    }

    @Test func expectedReadMaskSyslIsEmpty() {
        // SYSL never reads Rt (it WRITES Rt — see expectedWriteMask).
        let d = decode(0xD52B_7C20, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedWriteMaskBlIsLr() {
        let d = decode(0x9400_0000, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == (UInt64(1) << 30))
    }

    @Test func expectedWriteMaskMrsExtractsRt() {
        let d = decode(0xD53B_D040, at: 0) // MRS X0
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 1)
    }

    @Test func expectedWriteMaskSyslExtractsRt() {
        // SYSL X0, ... — writes X0 (Rt = 0).
        let d = decode(0xD52B_7C20, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 1)
    }

    @Test func expectedWriteMaskZeroForB() {
        let d = decode(0x1400_0000, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 0)
    }

    @Test func expectedFlagEffectForFlagManipulators() {
        #expect(BESSemanticAttributes.expectedFlagEffect(for: .cfinv) == [.writesC, .readsC])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: .xaflag) == [.nzcv, .readsNZCV])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: .axflag) == [.nzcv, .readsNZCV])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: .bCond) == .readsNZCV)
        #expect(BESSemanticAttributes.expectedFlagEffect(for: .nop) == FlagEffect.none)
    }

    @Test func expectedBranchClassCompareBranchFamily() {
        for m: Mnemonic in [.cbgt, .cbge, .cbhi, .cbhs, .cbeq, .cbne, .cblt, .cblo,
                            .cbbgt, .cbbge, .cbbhi, .cbbhs, .cbbeq, .cbbne,
                            .cbhgt, .cbhge, .cbhhi, .cbhhs, .cbheq, .cbhne]
        {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .conditional)
        }
    }

    @Test func expectedReadMaskCompareBranchReadsBothRegisters() {
        // CBGT w1, w2, #16 — register form reads Rt + Rm.
        let reg = decode(0x7400_0000 | 2 << 16 | 4 << 5 | 1)
        #expect(reg.mnemonic == .cbgt)
        let r = BESSemanticAttributes.expectedReadMask(for: reg)
        #expect(r?.required == ((UInt64(1) << 1) | (UInt64(1) << 2)))
        // CBBGT / CBHGT byte/halfword forms read both registers too.
        let byte = decode(0x7400_0000 | 2 << 16 | 0b10 << 14 | 4 << 5 | 1)
        #expect(byte.mnemonic == .cbbgt)
        #expect(BESSemanticAttributes.expectedReadMask(for: byte)?.required
            == ((UInt64(1) << 1) | (UInt64(1) << 2)))
        // CBGT w1, #5, #16 — immediate form reads only Rt.
        let imm = decode(0x7500_0000 | 5 << 15 | 4 << 5 | 1)
        #expect(imm.mnemonic == .cbgt)
        let ri = BESSemanticAttributes.expectedReadMask(for: imm)
        #expect(ri?.required == (UInt64(1) << 1))
    }

    @Test func expectedReadMaskMrrsIsEmpty() {
        // MRRS reads the system register only (it writes the GP pair).
        let d = decode(0xD570_0006)
        #expect(d.mnemonic == .mrrs)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedReadMaskMsrrReadsThePair() {
        let d = decode(0xD550_0006)
        #expect(d.mnemonic == .msrr)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == ((UInt64(1) << 6) | (UInt64(1) << 7)))
    }

    @Test func expectedReadMaskSyspAliasedReadsPair() {
        // TLBIP VAE1OS, x4, x5 — (op1=0, CRn=8, CRm=1, op2=1) is aliased.
        let d = decode(0xD548_0000 | 8 << 12 | 1 << 8 | 1 << 5 | 4)
        #expect(d.mnemonic == .sysp)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == ((UInt64(1) << 4) | (UInt64(1) << 5)))
        #expect(r?.required == d.semanticReads.mask)
    }

    @Test func expectedReadMaskSyspGenericReadsPair() {
        // Generic SYSP (no TLBIP alias) with Rt != 31 renders the pair.
        let d = decode(0xD548_0000 | 2)
        #expect(d.mnemonic == .sysp)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == ((UInt64(1) << 2) | (UInt64(1) << 3)))
    }

    @Test func expectedReadMaskSyspGenericRt31IsEmpty() {
        let d = decode(0xD548_0000 | 31)
        #expect(d.mnemonic == .sysp)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedReadMaskSyspAliasedRt31MatchesDecodedReads() {
        // Aliased SYSP with Rt == 31 renders the xzr pair; checker and
        // decoder agree on the encoding-31 bit (the pair collapses to one
        // canonical index).
        let d = decode(0xD548_0000 | 8 << 12 | 1 << 8 | 1 << 5 | 31)
        #expect(d.mnemonic == .sysp)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == (UInt64(1) << 31))
        #expect(r?.required == d.semanticReads.mask)
    }

    @Test func expectedWriteMaskMrrsWritesThePair() {
        let d = decode(0xD570_0006)
        #expect(d.mnemonic == .mrrs)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d)
            == ((UInt64(1) << 6) | (UInt64(1) << 7)))
    }

    @Test func expectedWriteMaskSyslAliasedGatesOnRt() {
        // GCSPOPM (op1=3, CRn=7, CRm=7, op2=1) is `.optReg`: Rt != 31
        // writes Rt; Rt == 31 writes nothing.
        let withReg = decode(0xD52B_7725)
        #expect(withReg.mnemonic == .sysl)
        #expect(BESSemanticAttributes.expectedWriteMask(for: withReg) == (UInt64(1) << 5))
        let bare = decode(0xD52B_773F)
        #expect(bare.mnemonic == .sysl)
        #expect(BESSemanticAttributes.expectedWriteMask(for: bare) == 0)
    }

    @Test func besSemanticIssuePublicInit() {
        let issue = BESSemanticIssue(field: "f", actual: "a", expected: "e")
        #expect(issue.field == "f")
        #expect(issue.actual == "a")
        #expect(issue.expected == "e")
        let same = BESSemanticIssue(field: "f", actual: "a", expected: "e")
        #expect(issue == same)
    }

    @Test func besExpectedReadsPublicInit() {
        let r = BESExpectedReads(required: 1, allowed: 2)
        #expect(r.required == 1)
        #expect(r.allowed == 2)
    }

    /// `.msr` path of `expectedReadMask`: a real MSR-register draft
    /// produces a mask whose required bit matches Rt (the last register
    /// operand).
    @Test func expectedReadMaskForMsrExtractsRt() {
        let d = decode(0xD51B_D040, at: 0) // MSR ..., X0
        #expect(d.mnemonic == .msr)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 1) // X0 bit
        #expect(r?.allowed == 1)
    }

    /// `.msr` defensive path: artificial draft with NO register operand
    /// — the `lastRegisterMask` returns nil → 0/0xFFFF... fallback.
    @Test func expectedReadMaskForMsrWithoutRegisterReturnsWildcard() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .msr,
            category: .branchesExceptionSystem,
            operands: [.systemRegister(SystemRegisterEncoding(op0: 3, op1: 0, crn: 0, crm: 0, op2: 0))],
        )
        let r = BESSemanticAttributes.expectedReadMask(for: weird)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0xFFFF_FFFF_FFFF_FFFF)
    }

    /// Variable-Rn case with operand list missing the register (defensive):
    /// hits the `firstRegisterMask` nil branch.
    @Test func expectedReadMaskForBrWithoutRegisterReturnsWildcard() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [], // no register
        )
        let r = BESSemanticAttributes.expectedReadMask(for: weird)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0xFFFF_FFFF_FFFF_FFFF)
    }

    /// `expectedReadMask` default branch — pass a non-BES mnemonic. The
    /// switch only enumerates BES mnemonics; anything else returns nil
    /// so the checker defers to the decoder.
    @Test func expectedReadMaskForNonBesMnemonicReturnsNil() {
        let foreign = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedReadMask(for: foreign) == nil)
    }

    /// `expectedWriteMask` default branch — pass a non-BES mnemonic.
    @Test func expectedWriteMaskForNonBesMnemonicReturnsNil() {
        let foreign = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedWriteMask(for: foreign) == nil)
    }

    /// `expectedWriteMask` MRS-empty-operand defensive: returns 0 via
    /// the `?? 0` fallback when there's no register operand.
    @Test func expectedWriteMaskForMrsWithoutRegister() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .mrs,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedWriteMask(for: weird) == 0)
    }

    @Test func verifyRejectsSysWithMissingRtRead() {
        // DC CVAC X0 reads X0 (needsReg=true). Mutate the draft to
        // remove the read — checker must flag semanticReads.missing.
        let d = mutated(decode(0xD50B_7A20, at: 0), semanticReads: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func verifyRejectsSysWithExtraneousRtRead() {
        // IC IALLUIS (needsReg=false) shouldn't read Rt. Mutate the
        // draft to add an extraneous read — checker must flag extraneous.
        let d = mutated(decode(0xD508_711F, at: 0), semanticReads: .empty.inserting(.x(5)))
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func verifyRejectsSyslWithMissingRtWrite() {
        // SYSL X0, ... writes X0. Mutate the draft to drop the write —
        // checker must flag semanticWrites.
        let d = mutated(decode(0xD52B_7C20, at: 0), semanticWrites: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }
}

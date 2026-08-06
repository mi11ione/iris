// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates `BESSemanticChecker.verify(draft:)` across every BES branch
/// class.
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
        let d = mutated(decode(0x1400_0000, at: 0), branchClass: .indirect)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "branchClass")
    }

    @Test func verifyRejectsExtraneousSemanticReads() {
        let d = mutated(decode(0x1400_0000, at: 0), semanticReads: .empty.inserting(.x(5)))
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func verifyRejectsMissingSemanticReads() {
        let d = mutated(decode(0xD61F_0000, at: 0), semanticReads: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func verifyRejectsWrongSemanticWrites() {
        let d = mutated(decode(0x9400_0000, at: 0), semanticWrites: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }

    @Test func firstRegisterMaskFromOperandList() {
        let ops: Instruction.Operands = [.unsignedImmediate(value: 1, width: 4), .register(.x(5)), .register(.x(7))]
        #expect(BESSemanticAttributes.firstRegisterMask(ops) == (UInt64(1) << 5))
    }

    @Test func firstRegisterMaskAbsent() {
        let ops: Instruction.Operands = [.unsignedImmediate(value: 1, width: 4)]
        #expect(BESSemanticAttributes.firstRegisterMask(ops) == nil)
    }

    @Test func lastRegisterMaskFromOperandList() {
        let ops: Instruction.Operands = [.register(.x(3)), .unsignedImmediate(value: 1, width: 4), .register(.x(9))]
        #expect(BESSemanticAttributes.lastRegisterMask(ops) == (UInt64(1) << 9))
    }

    @Test func lastRegisterMaskAbsent() {
        #expect(BESSemanticAttributes.lastRegisterMask([]) == nil)
    }

    @Test func firstTwoRegistersMask() {
        let ops: Instruction.Operands = [.register(.x(2)), .register(.x(5)), .register(.x(7))]
        let mask = BESSemanticAttributes.firstTwoRegistersMask(ops)
        #expect(mask == ((UInt64(1) << 2) | (UInt64(1) << 5)))
    }

    @Test func firstTwoRegistersMaskWithOnlyOne() {
        let ops: Instruction.Operands = [.register(.x(2)), .unsignedImmediate(value: 1, width: 4)]
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
        let d = decode(0xD508_711F, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0)
    }

    @Test func expectedReadMaskSysWithRegAliasIsRt() {
        let d = decode(0xD50B_7A25, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        let x5Bit = UInt64(1) << 5
        #expect(r?.required == x5Bit)
        #expect(r?.allowed == x5Bit)
    }

    @Test func expectedReadMaskSysUnknownAliasFallback() {
        let d = decode(0xD509_2380, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 1)
    }

    @Test func expectedReadMaskSysUnknownAliasRtZrNoRead() {
        let d = decode(0xD509_239F, at: 0)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 0)
    }

    @Test func expectedReadMaskSyslIsEmpty() {
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
        let d = decode(0xD53B_D040, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 1)
    }

    @Test func expectedWriteMaskSyslExtractsRt() {
        let d = decode(0xD52B_7C20, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 1)
    }

    @Test func expectedWriteMaskZeroForB() {
        let d = decode(0x1400_0000, at: 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 0)
    }

    @Test func expectedFlagEffectForFlagManipulators() {
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD500_401F, at: 0)) == [.writesC, .readsC])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD500_403F, at: 0)) == [.nzcv, .readsNZCV])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD500_405F, at: 0)) == [.nzcv, .readsNZCV])
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0x5400_0000, at: 0)) == .readsNZCV)
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD503_201F, at: 0)) == FlagEffect.none)
    }

    @Test func expectedFlagEffectFollowsTheNZCVSystemRegister() {
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD51B_4200, at: 0)) == .nzcv)
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD53B_4200, at: 0)) == .readsNZCV)
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD51B_4020, at: 0)) == FlagEffect.none)
        #expect(BESSemanticAttributes.expectedFlagEffect(for: decode(0xD53B_4020, at: 0)) == FlagEffect.none)
        #expect(BESSemanticAttributes.namesNZCV(0xD51B_4200))
        #expect(!BESSemanticAttributes.namesNZCV(0xD51B_4020))
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
        let reg = decode(0x7400_0000 | 2 << 16 | 4 << 5 | 1)
        #expect(reg.mnemonic == .cbgt)
        let r = BESSemanticAttributes.expectedReadMask(for: reg)
        #expect(r?.required == ((UInt64(1) << 1) | (UInt64(1) << 2)))
        let byte = decode(0x7400_0000 | 2 << 16 | 0b10 << 14 | 4 << 5 | 1)
        #expect(byte.mnemonic == .cbbgt)
        #expect(BESSemanticAttributes.expectedReadMask(for: byte)?.required
            == ((UInt64(1) << 1) | (UInt64(1) << 2)))
        let imm = decode(0x7500_0000 | 5 << 15 | 4 << 5 | 1)
        #expect(imm.mnemonic == .cbgt)
        let ri = BESSemanticAttributes.expectedReadMask(for: imm)
        #expect(ri?.required == (UInt64(1) << 1))
    }

    @Test func expectedReadMaskMrrsIsEmpty() {
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
        let d = decode(0xD548_0000 | 8 << 12 | 1 << 8 | 1 << 5 | 4)
        #expect(d.mnemonic == .sysp)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == ((UInt64(1) << 4) | (UInt64(1) << 5)))
        #expect(r?.required == d.semanticReads.mask)
    }

    @Test func expectedReadMaskSyspGenericReadsPair() {
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

    @Test func expectedReadMaskForMsrExtractsRt() {
        let d = decode(0xD51B_D040, at: 0)
        #expect(d.mnemonic == .msr)
        let r = BESSemanticAttributes.expectedReadMask(for: d)
        #expect(r?.required == 1)
        #expect(r?.allowed == 1)
    }

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

    @Test func expectedReadMaskForBrWithoutRegisterReturnsWildcard() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .br,
            category: .branchesExceptionSystem,
            operands: [],
        )
        let r = BESSemanticAttributes.expectedReadMask(for: weird)
        #expect(r?.required == 0)
        #expect(r?.allowed == 0xFFFF_FFFF_FFFF_FFFF)
    }

    @Test func expectedReadMaskForNonBesMnemonicReturnsNil() {
        let foreign = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedReadMask(for: foreign) == nil)
    }

    @Test func expectedWriteMaskForNonBesMnemonicReturnsNil() {
        let foreign = Instruction(
            address: 0, encoding: 0, mnemonic: .add,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedWriteMask(for: foreign) == nil)
    }

    @Test func expectedWriteMaskForMrsWithoutRegister() {
        let weird = Instruction(
            address: 0, encoding: 0, mnemonic: .mrs,
            category: .branchesExceptionSystem,
            operands: [],
        )
        #expect(BESSemanticAttributes.expectedWriteMask(for: weird) == 0)
    }

    @Test func verifyRejectsSysWithMissingRtRead() {
        let d = mutated(decode(0xD50B_7A20, at: 0), semanticReads: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func verifyRejectsSysWithExtraneousRtRead() {
        let d = mutated(decode(0xD508_711F, at: 0), semanticReads: .empty.inserting(.x(5)))
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func verifyRejectsSyslWithMissingRtWrite() {
        let d = mutated(decode(0xD52B_7C20, at: 0), semanticWrites: .empty)
        let issue = BESSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }

    @Test func verifyAcceptsHintSpacePac() {
        for word: UInt32 in [
            0xD503_20FF,
            0xD503_211F, 0xD503_215F, 0xD503_219F, 0xD503_21DF,
            0xD503_231F, 0xD503_233F, 0xD503_235F, 0xD503_237F,
            0xD503_239F, 0xD503_23BF, 0xD503_23DF, 0xD503_23FF,
        ] {
            #expect(BESSemanticChecker.verify(decode(word, at: 0)) == nil,
                    "checker rejected hint-space PAC 0x\(String(word, radix: 16))")
        }
    }

    @Test func expectedMasksHintSpacePacSpForms() {
        let x30: UInt64 = 1 << 30
        let sp: UInt64 = 1 << 31
        for word: UInt32 in [0xD503_233F, 0xD503_237F, 0xD503_23BF, 0xD503_23FF] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required == (x30 | sp))
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.allowed == (x30 | sp))
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == x30)
        }
    }

    @Test func expectedMasksHintSpacePacZeroFormsAndXpaclri() {
        let x30: UInt64 = 1 << 30
        for word: UInt32 in [0xD503_231F, 0xD503_235F, 0xD503_239F, 0xD503_23DF, 0xD503_20FF] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required == x30)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.allowed == x30)
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == x30)
        }
    }

    @Test func expectedMasksHintSpacePac1716Forms() {
        let x16: UInt64 = 1 << 16
        let x17: UInt64 = 1 << 17
        for word: UInt32 in [0xD503_211F, 0xD503_215F, 0xD503_219F, 0xD503_21DF] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required == (x16 | x17))
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.allowed == (x16 | x17))
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == x17)
        }
    }

    @Test func verifyRejectsHintSpacePacWithMissingReads() {
        let d = mutated(decode(0xD503_233F, at: 0), semanticReads: .empty)
        #expect(BESSemanticChecker.verify(d)?.field == "semanticReads.missing")
    }

    @Test func verifyRejectsHintSpacePacWithMissingWrite() {
        let d = mutated(decode(0xD503_237F, at: 0), semanticWrites: .empty)
        #expect(BESSemanticChecker.verify(d)?.field == "semanticWrites")
    }

    @Test func expectedBranchClassCoversTheNewReturnsAndTIndex() {
        for m: Mnemonic in [.retaasppc, .retabsppc, .retaasppcr, .retabsppcr, .texit, .texitNb] {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .return)
        }
        #expect(BESSemanticAttributes.expectedBranchClass(for: .tenter) == .exception)
        #expect(BESSemanticAttributes.expectedBranchClass(for: .tenterNb) == .exception)
        for m: Mnemonic in [.tchangef, .tchangefNb, .tchangeb, .tchangebNb,
                            .pacm, .stshh, .shuh, .stcph, .dfb]
        {
            #expect(BESSemanticAttributes.expectedBranchClass(for: m) == .none)
        }
    }

    @Test func expectedMasksForTheNewHintAndBarrierAliases() {
        for word: UInt32 in [0xD503_24FF, 0xD503_261F, 0xD503_265F, 0xD503_269F, 0xD503_3C9F] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.allowed == 0)
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 0)
            #expect(BESSemanticChecker.verify(d) == nil)
        }
    }

    @Test func expectedMasksForTheImmediateAndRegisterFormReturns() {
        let x30: UInt64 = 1 << 30
        let sp: UInt64 = 1 << 31
        for word: UInt32 in [0x5500_003F, 0x5520_003F] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required == (x30 | sp))
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 0)
        }
        for (word, modifier) in [(UInt32(0xD65F_0BE5), UInt64(5)), (UInt32(0xD65F_0FE0), UInt64(0))] {
            let d = decode(word, at: 0)
            #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required
                == (x30 | (UInt64(1) << modifier)))
            #expect(BESSemanticAttributes.expectedWriteMask(for: d) == 0)
        }
    }

    @Test func expectedMasksForTIndex() {
        let d = decode(0xD580_00A2, at: 0)
        #expect(BESSemanticAttributes.expectedReadMask(for: d)?.required == UInt64(1) << 5)
        #expect(BESSemanticAttributes.expectedWriteMask(for: d) == UInt64(1) << 2)
        let imm = decode(0xD590_0C77, at: 0)
        #expect(BESSemanticAttributes.expectedReadMask(for: imm)?.required == 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: imm) == UInt64(1) << 23)
        let enter = decode(0xD4E0_0020, at: 0)
        #expect(BESSemanticAttributes.expectedReadMask(for: enter)?.allowed == 0)
        #expect(BESSemanticAttributes.expectedWriteMask(for: enter) == 0)
    }

    @Test func verifyRejectsTIndexWithAWrongDestination() {
        let d = mutated(decode(0xD580_00A2, at: 0), semanticWrites: .empty)
        #expect(BESSemanticChecker.verify(d)?.field == "semanticWrites")
    }

    @Test func expectedMasksForTheNewSysAliasKinds() {
        let optionalComma = decode(0xD508_8102, at: 0)
        #expect(optionalComma.text == "tlbi vmalle1os, x2")
        #expect(BESSemanticAttributes.expectedReadMask(for: optionalComma)?.required == UInt64(1) << 2)
        let bare = decode(0xD508_811F, at: 0)
        #expect(bare.text == "tlbi vmalle1os")
        #expect(BESSemanticAttributes.expectedReadMask(for: bare)?.allowed == 0)
        let reversed = decode(0xD528_C302, at: 0)
        #expect(reversed.text == "gicr x2, cdia")
        #expect(BESSemanticAttributes.expectedWriteMask(for: reversed) == UInt64(1) << 2)
        let reversedZero = decode(0xD528_C31F, at: 0)
        #expect(reversedZero.text == "gicr xzr, cdia")
        #expect(BESSemanticAttributes.expectedWriteMask(for: reversedZero) == UInt64(1) << 31)
    }

    @Test func expectedMasksFallBackWhenTheOperandListIsEmpty() {
        let returnForm = mutated(decode(0xD65F_0BE5, at: 0), operands: [])
        #expect(BESSemanticAttributes.expectedReadMask(for: returnForm)?.required == UInt64(1) << 30)
        let change = mutated(decode(0xD580_00A2, at: 0), operands: [])
        #expect(BESSemanticAttributes.expectedWriteMask(for: change) == 0)
        #expect(BESSemanticAttributes.expectedReadMask(for: change)?.required == 0)
    }
}

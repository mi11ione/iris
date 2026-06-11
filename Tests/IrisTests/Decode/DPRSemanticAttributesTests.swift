// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates the per-mnemonic semantic-attribute table + the
/// `DPRSemanticChecker.verify(draft:)` entry point. Covers every
/// branch of `expectedFlagEffect`, `expectedReadMask`, `expectedWriteMask`,
/// `registerMaskAt`, plus every `DPRSemanticIssue` field-mismatch path.
@Suite("DPR / Semantic attribute checker")
struct DPRSemanticAttributesTests {
    @Test func everyDPRRecordPassesSemanticCheck() {
        // Sample one encoding per mnemonic family; each must pass the checker.
        let cases: [UInt32] = [
            0x8B02_0020, // add
            0xAB02_0020, // adds
            0xCB02_0020, // sub
            0xEB02_0020, // subs
            0xAB02_003F, // cmn alias
            0xEB02_003F, // cmp alias
            0xCB01_03E0, // neg alias
            0xEB01_03E0, // negs alias
            0x8B22_6020, // add extended
            0xEB21_63FF, // cmp extended alias
            0x8A02_0020, // and
            0xAA02_0020, // orr
            0xCA02_0020, // eor
            0xEA02_0020, // ands
            0x8A22_0020, // bic
            0xAA22_0020, // orn
            0xCA22_0020, // eon
            0xEA22_0020, // bics
            0xAA02_03E0, // mov alias
            0xAA22_03E0, // mvn alias
            0xEA02_003F, // tst alias
            0x9A02_0020, // adc
            0xBA02_0020, // adcs
            0xDA02_0020, // sbc
            0xFA02_0020, // sbcs
            0xDA01_03E0, // ngc alias
            0xFA01_03E0, // ngcs alias
            0xFA42_0025, // ccmp reg
            0xFA40_0825, // ccmp imm
            0xBA42_0025, // ccmn reg
            0x9A82_0020, // csel
            0x9A82_0420, // csinc
            0xDA82_0020, // csinv
            0xDA82_0420, // csneg
            0x9A9F_07E0, // cset alias
            0xDA9F_03E0, // csetm alias
            0x9A81_0420, // cinc alias
            0xDA81_0020, // cinv alias
            0xDA81_0420, // cneg alias
            0x9B02_0C20, // madd
            0x9B02_8C20, // msub
            0x9B22_0C20, // smaddl
            0x9B22_8C20, // smsubl
            0x9BA2_0C20, // umaddl
            0x9BA2_8C20, // umsubl
            0x9B42_7C20, // smulh
            0x9BC2_7C20, // umulh
            0x9B02_7C20, // mul alias
            0x9B02_FC20, // mneg alias
            0x9B22_7C20, // smull alias
            0x9B22_FC20, // smnegl alias
            0x9BA2_7C20, // umull alias
            0x9BA2_FC20, // umnegl alias
            0x9AC2_0820, // udiv
            0x9AC2_0C20, // sdiv
            0x9AC2_2020, // lslv → lsl
            0x9AC2_2420, // lsrv → lsr
            0x9AC2_2820, // asrv → asr
            0x9AC2_2C20, // rorv → ror
            0x1AC2_4020, // crc32b
            0x1AC2_4420, // crc32h
            0x1AC2_4820, // crc32w
            0x9AC2_4C20, // crc32x
            0x1AC2_5020, // crc32cb
            0x1AC2_5420, // crc32ch
            0x1AC2_5820, // crc32cw
            0x9AC2_5C20, // crc32cx
            0xDAC0_0020, // rbit
            0xDAC0_0420, // rev16
            0xDAC0_0820, // rev32 (sf=1)
            0xDAC0_0C20, // rev (sf=1)
            0xDAC0_1020, // clz
            0xDAC0_1420, // cls
        ]
        for encoding in cases {
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic != .undefined, "encoding \(String(format: "0x%08x", encoding)) decoded as undefined")
            let issue = DPRSemanticChecker.verify(d)
            #expect(issue == nil, "encoding \(String(format: "0x%08x", encoding)) (\(d.mnemonic.rawValue)) → \(String(describing: issue))")
        }
    }

    @Test func undefinedRecordsSkipChecker() {
        let d = Instruction(address: 0, encoding: 0xDEAD_BEEF, mnemonic: .undefined, category: .undefined)
        #expect(DPRSemanticChecker.verify(d) == nil)
    }

    /// Minimal DPR draft carrying a mnemonic (and operands, for RMIF's
    /// mask-dependent write set). `expectedFlagEffect` reads only the
    /// mnemonic, except for RMIF, which reads the imm4 mask at operand[2].
    private func dprDraft(_ m: Mnemonic, operands: [Operand] = []) -> Instruction {
        Instruction(address: 0, encoding: 0, mnemonic: m, category: .dataProcessingRegister, operands: operands)
    }

    @Test func writeOnlyFlagSettersReportNzcv() {
        for m: Mnemonic in [.adds, .subs, .ands, .bics, .cmp, .cmn, .tst, .negs] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .nzcv, "\(m.rawValue)")
        }
    }

    @Test func carryConsumersReadCarry() {
        for m: Mnemonic in [.adc, .sbc, .ngc] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .readsC, "\(m.rawValue)")
        }
        for m: Mnemonic in [.adcs, .sbcs, .ngcs] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.nzcv, .readsC], "\(m.rawValue)")
        }
    }

    @Test func conditionConsumersReadNzcv() {
        for m: Mnemonic in [.ccmp, .ccmn] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.nzcv, .readsNZCV], "\(m.rawValue)")
        }
        for m: Mnemonic in [.csel, .csinc, .csinv, .csneg, .cset, .csetm, .cinc, .cinv, .cneg] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .readsNZCV, "\(m.rawValue)")
        }
    }

    @Test func setfWritesNzvPreservingCarry() {
        for m: Mnemonic in [.setf8, .setf16] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == [.writesN, .writesZ, .writesV], "\(m.rawValue)")
        }
    }

    @Test func rmifWritesMaskSelectedFlags() {
        /// operand[2] is the imm4 mask: bit3→N, bit2→Z, bit1→C, bit0→V.
        func rmif(mask: UInt64) -> Instruction {
            dprDraft(.rmif, operands: [
                .unsignedImmediate(value: 0, width: 6),
                .unsignedImmediate(value: 0, width: 6),
                .unsignedImmediate(value: mask, width: 4),
            ])
        }
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b1111)) == .nzcv)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b1000)) == .writesN)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b0010)) == .writesC)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: rmif(mask: 0b0000)) == .none)
    }

    @Test func nonFlagMnemonicsReportNone() {
        for m: Mnemonic in [.add, .sub, .and, .orr, .mov, .madd, .udiv, .rbit] {
            #expect(DPRSemanticAttributes.expectedFlagEffect(for: dprDraft(m)) == .none)
        }
    }

    @Test func semanticIssueInit() {
        let issue = DPRSemanticIssue(field: "flagEffect", actual: "none", expected: "nzcv")
        #expect(issue.field == "flagEffect")
        #expect(issue.actual == "none")
        #expect(issue.expected == "nzcv")
    }

    @Test func expectedReadsInit() {
        let reads = DPRExpectedReads(required: 0x2, allowed: 0x6)
        #expect(reads.required == 0x2)
        #expect(reads.allowed == 0x6)
    }

    @Test func registerMaskAtPlainRegisterReturnsBit() {
        let ops: [Operand] = [.register(.x(5))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == (1 << 5))
    }

    @Test func registerMaskAtZeroRegisterReturnsZero() {
        let ops: [Operand] = [.register(.xzr())]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtIndexOutOfRangeReturnsZero() {
        let ops: [Operand] = [.register(.x(1))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 5, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtNegativeIndexReturnsZero() {
        let ops: [Operand] = [.register(.x(1))]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: -1, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtShiftedRegisterUnwrappedReturnsBit() {
        let ops: [Operand] = [.shiftedRegister(reg: .x(3), shift: .lsl, amount: 1)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == (1 << 3))
    }

    @Test func registerMaskAtShiftedRegisterNoUnwrapReturnsZero() {
        let ops: [Operand] = [.shiftedRegister(reg: .x(3), shift: .lsl, amount: 1)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtExtendedRegisterUnwrappedReturnsBit() {
        let ops: [Operand] = [.extendedRegister(reg: .x(7), extend: .uxtx, shift: 0)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == (1 << 7))
    }

    @Test func registerMaskAtExtendedRegisterNoUnwrapReturnsZero() {
        let ops: [Operand] = [.extendedRegister(reg: .x(7), extend: .uxtx, shift: 0)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: false)
        #expect(mask == 0)
    }

    @Test func registerMaskAtUnsupportedOperandReturnsZero() {
        let ops: [Operand] = [.conditionCode(.eq)]
        let mask = DPRSemanticAttributes.registerMaskAt(operands: ops, index: 0, unwrapShiftExtend: true)
        #expect(mask == 0)
    }

    @Test func expectedReadMaskForUnknownMnemonicIsNil() {
        // .b is a BES-family mnemonic — DPR's switch returns nil for it.
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .b,
            category: .dataProcessingRegister,
        )
        #expect(DPRSemanticAttributes.expectedReadMask(for: draft) == nil)
    }

    @Test func expectedWriteMaskForUnknownMnemonicIsNil() {
        let draft = Instruction(
            address: 0, encoding: 0, mnemonic: .b,
            category: .dataProcessingRegister,
        )
        #expect(DPRSemanticAttributes.expectedWriteMask(for: draft) == nil)
    }

    @Test func wrongBranchClassReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), branchClass: .direct)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "branchClass")
    }

    @Test func wrongMemoryAccessReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), memoryAccess: .load)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "memoryAccess")
    }

    @Test func wrongMemoryOrderingReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), memoryOrdering: .acquire)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "memoryOrdering")
    }

    @Test func wrongCategoryReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), category: .branchesExceptionSystem)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "category")
    }

    @Test func wrongFlagEffectReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), flagEffect: .nzcv)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "flagEffect")
    }

    @Test func missingSemanticReadsReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), semanticReads: .empty)
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.missing")
    }

    @Test func extraneousSemanticReadsReturnsIssue() {
        // Add an unexpected register to the read set.
        let base = decode(0x8B02_0020, at: 0)
        let d = mutated(base, semanticReads: base.semanticReads.inserting(.x(10)))
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticReads.extraneous")
    }

    @Test func wrongSemanticWritesReturnsIssue() {
        let d = mutated(decode(0x8B02_0020, at: 0), semanticWrites: RegisterSet.empty.inserting(.x(20)))
        let issue = DPRSemanticChecker.verify(d)
        #expect(issue?.field == "semanticWrites")
    }

    //
    // The semantic checker derives expected masks from the draft's own
    // operand list, so a decoder bug that corrupts BOTH the operand list
    // AND the reads/writes in matching ways would pass the checker.
    // These tests assert exact reads/writes computed independently from
    // the encoding fields, catching that class of bug.

    @Test func addShiftedSemanticMasksMatchEncoding() {
        // ADD x0, x1, x2 → reads {x1, x2}, writes {x0}.
        let d = decode(0x8B02_0020, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func cmpAliasSemanticMasksDropRd() {
        // CMP x1, x2 (Rd=XZR) → reads {x1, x2}, writes {} (XZR dropped).
        let d = decode(0xEB02_003F, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func tstAliasSemanticMasksDropRd() {
        // TST x1, x2 → reads {x1, x2}, writes {}.
        let d = decode(0xEA02_003F, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func csetAliasSemanticMasksFromRnRmXZR() {
        // CSET x0, ne — Rn=Rm=XZR dropped → reads empty, writes {x0}.
        let d = decode(0x9A9F_07E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func csetmAliasSemanticMasks() {
        let d = decode(0xDA9F_03E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func cnegWithXZRSemanticMasksAllowZeroRead() {
        // CNEG x0, xzr, ne — Rn=XZR allowed by CNEG; reads dropped to 0,
        // writes {x0}.
        let d = decode(0xDA9F_07E0, at: 0)
        #expect(d.semanticReads.mask == 0)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func smaddlSemanticMasksThreeSource() {
        // SMADDL x0, w1, w2, x3 → reads {w1, w2, x3} (canonical-indexed all to 1/2/3), writes {x0}.
        let d = decode(0x9B22_0C20, at: 0)
        let expected = (UInt64(1) << 1) | (UInt64(1) << 2) | (UInt64(1) << 3)
        #expect(d.semanticReads.mask == expected)
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func smulhSemanticMasksNoRa() {
        // SMULH x0, x1, x2 → reads {x1, x2}, writes {x0} (no Ra).
        let d = decode(0x9B42_7C20, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func crc32xSemanticMasksWithMixedWidths() {
        // CRC32X w0, w1, x2 — reads {1, 2} (canonical indices), writes {0}.
        let d = decode(0x9AC2_4C20, at: 0)
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 2))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func rmifWithoutItsMaskOperandExpectsFullNZCV() {
        // The RMIF flag expectation reads the imm4 mask from operand[2];
        // a hand-built record without it falls back to the full set.
        let bare = Instruction(mnemonic: .rmif, category: .dataProcessingRegister)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: bare) == .nzcv)
        // Decoded RMIF with mask 0b1111 selects all four flags.
        let full = decode(0xBA01_842F, at: 0)
        #expect(DPRSemanticAttributes.expectedFlagEffect(for: full)
            == [.writesN, .writesZ, .writesC, .writesV])
    }
}

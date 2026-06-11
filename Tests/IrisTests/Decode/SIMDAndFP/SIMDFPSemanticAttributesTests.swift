// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates the SIMDFPSemanticAttributes utility — per-mnemonic flag /
/// memoryAccess / destination-reads-itself helpers — and the
/// SIMDFPSemanticChecker that enforces universal invariants on SIMD/FP
/// records.
@Suite("SIMD/FP / SIMDFPSemanticAttributes.expectedFlagEffect")
struct SIMDFPSemanticAttributesFlagEffectTests {
    @Test func fcmpExpectsNzcv() {
        #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: .fcmp) == .nzcv)
    }

    @Test func fcmpeExpectsNzcv() {
        #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: .fcmpe) == .nzcv)
    }

    @Test func fccmpReadsAndWritesNzcv() {
        #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: .fccmp) == [.nzcv, .readsNZCV])
    }

    @Test func fccmpeReadsAndWritesNzcv() {
        #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: .fccmpe) == [.nzcv, .readsNZCV])
    }

    @Test func fcselReadsNzcv() {
        // FCSEL consumes NZCV (the condition) but writes no flag.
        #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: .fcsel) == .readsNZCV)
    }

    @Test func nonCompareExpectsNone() {
        for m: Mnemonic in [.fadd, .fsub, .fmul, .fdiv, .fmov, .add, .sub] {
            #expect(SIMDFPSemanticAttributes.expectedFlagEffect(for: m) == .none)
        }
    }
}

/// Validates SIMDFPSemanticAttributes.expectedMemoryAccess.
@Suite("SIMD/FP / SIMDFPSemanticAttributes.expectedMemoryAccess")
struct SIMDFPSemanticAttributesMemoryAccessTests {
    @Test func multiStructureLoadsExpectLoad() {
        for m: Mnemonic in [.ld1, .ld2, .ld3, .ld4] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .load)
        }
    }

    @Test func multiStructureStoresExpectStore() {
        for m: Mnemonic in [.st1, .st2, .st3, .st4] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .store)
        }
    }

    @Test func replicateLoadsExpectLoad() {
        for m: Mnemonic in [.ld1r, .ld2r, .ld3r, .ld4r] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .load)
        }
    }

    @Test func scalarSimdLoadsExpectLoad() {
        for m: Mnemonic in [.ldr, .ldur, .ldp, .ldnp] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .load)
        }
    }

    @Test func scalarSimdStoresExpectStore() {
        for m: Mnemonic in [.str, .stur, .stp, .stnp] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .store)
        }
    }

    @Test func nonMemoryMnemonicsExpectNone() {
        for m: Mnemonic in [.fadd, .fsub, .fmov, .fcmp, .add, .sqadd] {
            #expect(SIMDFPSemanticAttributes.expectedMemoryAccess(for: m) == .none)
        }
    }
}

/// Validates SIMDFPSemanticAttributes.destinationReadsItself.
@Suite("SIMD/FP / SIMDFPSemanticAttributes.destinationReadsItself")
struct SIMDFPSemanticAttributesDestReadTests {
    @Test func accumulatingMnemonicsReadDestination() {
        let accum: [Mnemonic] = [
            .mla, .mls, .fmla, .fmls, .fmlal, .fmlal2, .fmlsl, .fmlsl2,
            .sqdmlal, .sqdmlsl, .sqdmlal2, .sqdmlsl2,
            .sqrdmlah, .sqrdmlsh,
            .smlal, .smlal2, .smlsl, .smlsl2,
            .umlal, .umlal2, .umlsl, .umlsl2,
            .sdot, .udot, .usdot, .sudot, .bfdot,
            .bfmlalb, .bfmlalt, .bfmmla,
            .smmla, .ummla, .usmmla,
            .sadalp, .uadalp,
            .saba, .uaba, .sabal, .sabal2, .uabal, .uabal2,
            .bsl, .bit, .bif,
            .ins, .sli, .sri, .tbx,
        ]
        for m in accum {
            #expect(SIMDFPSemanticAttributes.destinationReadsItself(for: m),
                    "expected destinationReadsItself for \(m.rawValue)")
        }
    }

    @Test func nonAccumulatingMnemonicsDoNotReadDestination() {
        for m: Mnemonic in [.add, .sub, .mul, .fadd, .fsub, .fmov, .neg, .abs] {
            #expect(!SIMDFPSemanticAttributes.destinationReadsItself(for: m))
        }
    }

    @Test func fmaddDoesNotReadDestinationItself() {
        // FMADD/FMSUB/FNMADD/FNMSUB have explicit Ra accumulator — Rd is
        // a pure write.
        for m: Mnemonic in [.fmadd, .fmsub, .fnmadd, .fnmsub] {
            #expect(!SIMDFPSemanticAttributes.destinationReadsItself(for: m))
        }
    }
}

/// Validates SIMDFPSemanticChecker.verify(draft:) for both passing
/// records and the universal-invariant mismatches it catches.
@Suite("SIMD/FP / SIMDFPSemanticChecker.verify")
struct SIMDFPSemanticCheckerTests {
    private func draft(
        mnemonic: Mnemonic,
        flagEffect: FlagEffect = .none,
        memoryAccess: MemoryAccess = .none,
        branchClass: BranchClass = .none,
        memoryOrdering: MemoryOrdering = [],
        category: Category = .simdAndFP,
        operands: [Operand] = [],
    ) -> Instruction {
        Instruction(
            address: 0,
            encoding: 0,
            mnemonic: mnemonic,
            branchClass: branchClass,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: flagEffect,
            category: category,
            operands: operands,
        )
    }

    @Test func undefinedRecordPassesCheck() {
        let d = draft(mnemonic: .undefined, category: .undefined)
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
    }

    @Test func validFaddRecordPasses() {
        let d = draft(mnemonic: .fadd)
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
    }

    @Test func validFcmpRecordPasses() {
        let d = draft(mnemonic: .fcmp, flagEffect: .nzcv)
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
    }

    @Test func validLD1RecordPasses() {
        let d = draft(mnemonic: .ld1, memoryAccess: .load)
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
    }

    @Test func wrongBranchClassReportsIssue() {
        let d = draft(mnemonic: .fadd, branchClass: .direct)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "branchClass")
        #expect(issue?.expected == "none")
    }

    @Test func wrongMemoryOrderingReportsIssue() {
        let d = draft(mnemonic: .fadd, memoryOrdering: .acquire)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "memoryOrdering")
    }

    @Test func wrongCategoryReportsIssue() {
        let d = draft(mnemonic: .fadd, category: .dataProcessingRegister)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "category")
        #expect(issue?.expected == "simdAndFP")
    }

    @Test func wrongFlagEffectForFAddReportsIssue() {
        let d = draft(mnemonic: .fadd, flagEffect: .nzcv)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "flagEffect")
    }

    @Test func wrongFlagEffectForFCmpReportsIssue() {
        // FCMP requires .nzcv but record has .none.
        let d = draft(mnemonic: .fcmp, flagEffect: .none)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "flagEffect")
    }

    @Test func wrongMemoryAccessForLDReportsIssue() {
        let d = draft(mnemonic: .ld1, memoryAccess: .none)
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "memoryAccess")
        #expect(issue?.expected == "load")
    }

    @Test func mslShiftInShiftedRegisterReportsIssue() {
        // MSL is valid only in .shiftAmount, not .shiftedRegister.
        let d = draft(mnemonic: .fadd, operands: [
            .shiftedRegister(reg: .x(0), shift: .msl, amount: 8),
        ])
        let issue = SIMDFPSemanticChecker.verify(d)
        #expect(issue?.field == "shift-kind-context")
    }

    @Test func mslShiftInShiftAmountIsAccepted() {
        // MSL inside .shiftAmount is valid.
        let d = draft(mnemonic: .movi, operands: [
            .shiftAmount(kind: .msl, amount: 8),
        ])
        #expect(SIMDFPSemanticChecker.verify(d) == nil)
    }

    @Test func nonMslShiftedRegisterAccepted() {
        // A non-MSL shift in .shiftedRegister is fine — the operand-context
        // discipline rejects only `.msl` there, not LSL.
        let d = draft(mnemonic: .fadd, operands: [
            .shiftedRegister(reg: .x(0), shift: .lsl, amount: 2),
        ])
        #expect(SIMDFPSemanticChecker.verify(d)?.field != "shift-kind-context")
    }

    @Test func verifyAgreesWithTheDecoderForLoadsStoresAndDataProcessing() {
        // Decoded vehicles spanning every read/write derivation arm:
        // multi-structure load/store (with and without writeback),
        // single-structure element forms (lane-preserving destination),
        // scalar FP compare, accumulating multiply, ORR in both its
        // immediate (read-modify-write) and register (pure-write) forms,
        // and the element-view FMOV destination.
        let words: [UInt32] = [
            0x0C40_0000, // ld4 {v0..v3.8b}, [x0]
            0x0C9F_0000, // st4 {v0..v3.8b}, [x0], #32 (writeback)
            0x0CDF_0000, // ld4 {v0..v3.8b}, [x0], #32 (writeback)
            0x0D40_0000, // ld1 {v0.b}[0], [x0] (element destination)
            0x0D00_0000, // st1 {v0.b}[0], [x0]
            0x1E21_2020, // fcmp s1, s2
            0x0E22_9420, // mla v0.8b, v1.8b, v2.8b
            0x0F00_9420, // orr v0.4h, #1, lsl #8 (vector immediate)
            0x0EA2_1C20, // orr v0.8b, v1.8b, v2.8b (register form)
            0x9EAF_0020, // fmov v0.d[1], x1
        ]
        for word in words {
            let d = decodeSIMD(word)
            #expect(d.category == .simdAndFP, "0x\(String(word, radix: 16))")
            let issue = SIMDFPSemanticChecker.verify(d)
            #expect(issue == nil, "0x\(String(word, radix: 16)) (\(d.mnemonic.name)): \(String(describing: issue))")
        }
    }

    @Test func verifyFlagsWrongSemanticReads() {
        let d = mutated(decodeSIMD(0x0E22_9420), semanticReads: .empty)
        #expect(SIMDFPSemanticChecker.verify(d)?.field == "semanticReads")
    }

    @Test func verifyFlagsWrongSemanticWrites() {
        let d = mutated(decodeSIMD(0x0E22_9420), semanticWrites: .empty)
        #expect(SIMDFPSemanticChecker.verify(d)?.field == "semanticWrites")
    }

    @Test func loadAndStoreMasksDeriveFromTheOperandList() {
        let v0 = UInt64(1) << 32
        let x0 = UInt64(1) << 0
        // LD1 single element: reads base + the lane-preserved destination;
        // writes the destination vector.
        let ld1e = decodeSIMD(0x0D40_0000)
        #expect(ld1e.mnemonic == .ld1)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: ld1e) == (x0 | v0))
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: ld1e) == v0)
        // ST4 with post-index writeback: reads v0..v3 + base; writes base.
        let st4wb = decodeSIMD(0x0C9F_0000)
        #expect(st4wb.mnemonic == .st4)
        let v0123 = v0 | v0 << 1 | v0 << 2 | v0 << 3
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: st4wb) == (x0 | v0123))
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: st4wb) == x0)
        // LD4 with writeback: writes v0..v3 + base; reads only the base.
        let ld4wb = decodeSIMD(0x0CDF_0000)
        #expect(ld4wb.mnemonic == .ld4)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: ld4wb) == x0)
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: ld4wb) == (x0 | v0123))
    }

    @Test func orrDestructivenessDependsOnOperandForm() {
        let v0 = UInt64(1) << 32
        // Vector-immediate ORR is a read-modify-write of Vd.
        let imm = decodeSIMD(0x0F00_9420)
        #expect(imm.mnemonic == .orr)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: imm) == v0)
        // Register-form ORR writes Vd without reading it.
        let reg = decodeSIMD(0x0EA2_1C20)
        #expect(reg.mnemonic == .orr)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: reg) == (v0 << 1 | v0 << 2))
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: reg) == v0)
    }

    @Test func elementViewDestinationIsAlsoRead() {
        // FMOV v0.d[1], x1 writes one lane and preserves the other, so
        // the destination vector is read as well as written.
        let d = decodeSIMD(0x9EAF_0020)
        #expect(d.mnemonic == .fmov)
        let v0 = UInt64(1) << 32
        let x1 = UInt64(1) << 1
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: d) == (x1 | v0))
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: d) == v0)
    }

    @Test func cryptoCategoryRecordsAreSkipped() {
        // AES/SHA share the op0 partition but belong to the crypto checker.
        let aese = decodeSIMD(0x4E28_48E5)
        #expect(aese.category == .crypto)
        #expect(SIMDFPSemanticChecker.verify(aese) == nil)
    }

    @Test func orderedSIMDFormsCarryTheirOrderingExpectations() {
        // LDAP1/STL1 and LDAPUR/STLUR rows of the ordering table, driven
        // through verify on decoded records.
        for word: UInt32 in [0x0D41_8420, 0x0D01_8420, 0x1D40_0820, 0x1D00_0820] {
            let d = decodeSIMD(word)
            #expect(SIMDFPSemanticChecker.verify(d) == nil, "0x\(String(word, radix: 16))")
        }
        #expect(SIMDFPSemanticAttributes.expectedMemoryOrdering(for: .ldap1) == [.acquire])
        #expect(SIMDFPSemanticAttributes.expectedMemoryOrdering(for: .stl1) == [.release])
        #expect(SIMDFPSemanticAttributes.expectedMemoryOrdering(for: .ldapur) == [.acquire])
        #expect(SIMDFPSemanticAttributes.expectedMemoryOrdering(for: .stlur) == [.release])
    }

    @Test func storeMasksWithoutAMemoryOperandAreNil() {
        let bare = Instruction(mnemonic: .st1, category: .simdAndFP)
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: bare) == nil)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: bare) == nil)
    }

    @Test func maskDerivationScansPastTrailingNonMemoryOperands() {
        // The memory operand need not be last; the scan walks backward
        // past trailing registers.
        let mem = MemoryOperand(base: .register(.x(1)), index: .x(2))
        let d = Instruction(
            mnemonic: .st1, category: .simdAndFP,
            operands: [
                .vectorRegister(VectorRegisterRef(registerIndex: 0, view: .full(arrangement: .b8))),
                .memory(mem),
                .register(.x(9)),
            ],
        )
        // Reads: stored register + base + index (the trailing x9 sits
        // after the memory operand and is not part of the stored data).
        let v0 = UInt64(1) << 32
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: d)
            == (v0 | (UInt64(1) << 1) | (UInt64(1) << 2)))
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: d) == 0)
    }

    @Test func registerBitContributionsCoverEveryOperandForm() {
        // Hand-built records drive the operand→bit projection through
        // every register-carrying operand form plus the zero-register and
        // non-register exclusions.
        let viaReads = { (ops: [Operand]) -> UInt64? in
            SIMDFPSemanticAttributes.expectedReadMask(for: Instruction(
                mnemonic: .fadd, category: .simdAndFP, operands: ops,
            ))
        }
        #expect(viaReads([.register(.x(0)), .register(.x(5))]) == (UInt64(1) << 5))
        #expect(viaReads([.register(.x(0)), .register(.xzr())]) == 0)
        #expect(viaReads([.register(.x(0)), .extendedRegister(reg: .x(7), extend: .uxtw, shift: 0)])
            == (UInt64(1) << 7))
        #expect(viaReads([.register(.x(0)), .extendedRegister(reg: .xzr(), extend: .uxtw, shift: 0)]) == 0)
        #expect(viaReads([.register(.x(0)), .shiftedRegister(reg: .xzr(), shift: .lsl, amount: 1)]) == 0)
        #expect(viaReads([.register(.x(0)), .unsignedImmediate(value: 3, width: 4)]) == 0)
    }
}

private func decodeSIMD(_ e: UInt32) -> Instruction {
    Iris.decode(e, at: 0)
}

/// Validates SIMDFPSemanticIssue / SIMDFPExpectedReads — the value
/// types returned by the checker. Round-trip equality and initializer
/// sanity.
@Suite("SIMD/FP / SIMDFPSemanticIssue value type")
struct SIMDFPSemanticIssueValueTests {
    @Test func issueInitializerCapturesFields() {
        let i = SIMDFPSemanticIssue(field: "flagEffect", actual: ".none", expected: ".nzcv")
        #expect(i.field == "flagEffect")
        #expect(i.actual == ".none")
        #expect(i.expected == ".nzcv")
    }

    @Test func issueEquatable() {
        let a = SIMDFPSemanticIssue(field: "f", actual: "a", expected: "e")
        let b = SIMDFPSemanticIssue(field: "f", actual: "a", expected: "e")
        let c = SIMDFPSemanticIssue(field: "g", actual: "a", expected: "e")
        #expect(a == b)
        #expect(a != c)
    }

    @Test func expectedReadsInitializerCapturesFields() {
        let r = SIMDFPExpectedReads(required: 0b1010, allowed: 0b1111)
        #expect(r.required == 0b1010)
        #expect(r.allowed == 0b1111)
    }

    @Test func expectedReadsEquatable() {
        let a = SIMDFPExpectedReads(required: 1, allowed: 2)
        let b = SIMDFPExpectedReads(required: 1, allowed: 2)
        let c = SIMDFPExpectedReads(required: 1, allowed: 3)
        #expect(a == b)
        #expect(a != c)
    }
}

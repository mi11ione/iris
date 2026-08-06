// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates the FEAT_LSFE floating-point atomic memory family: the complete
/// load and store mnemonic tables, their operand text, their atomic access and
/// acquire/release ordering, and the encodings the family leaves UNDEFINED.
@Suite("SIMD/FP / FEAT_LSFE floating-point atomics")
struct SIMDFPLSFEAtomicTests {
    static let loadForms: [(word: UInt32, text: String)] = [
        (0x3C37_02AF, "ldbfadd h23, h15, [x21]"),
        (0x3C37_42AF, "ldbfmax h23, h15, [x21]"),
        (0x3C37_52AF, "ldbfmin h23, h15, [x21]"),
        (0x3C37_62AF, "ldbfmaxnm h23, h15, [x21]"),
        (0x3C37_72AF, "ldbfminnm h23, h15, [x21]"),
        (0x3C77_02AF, "ldbfaddl h23, h15, [x21]"),
        (0x3C77_42AF, "ldbfmaxl h23, h15, [x21]"),
        (0x3C77_52AF, "ldbfminl h23, h15, [x21]"),
        (0x3C77_62AF, "ldbfmaxnml h23, h15, [x21]"),
        (0x3C77_72AF, "ldbfminnml h23, h15, [x21]"),
        (0x3CB7_02AF, "ldbfadda h23, h15, [x21]"),
        (0x3CB7_42AF, "ldbfmaxa h23, h15, [x21]"),
        (0x3CB7_52AF, "ldbfmina h23, h15, [x21]"),
        (0x3CB7_62AF, "ldbfmaxnma h23, h15, [x21]"),
        (0x3CB7_72AF, "ldbfminnma h23, h15, [x21]"),
        (0x3CF7_02AF, "ldbfaddal h23, h15, [x21]"),
        (0x3CF7_42AF, "ldbfmaxal h23, h15, [x21]"),
        (0x3CF7_52AF, "ldbfminal h23, h15, [x21]"),
        (0x3CF7_62AF, "ldbfmaxnmal h23, h15, [x21]"),
        (0x3CF7_72AF, "ldbfminnmal h23, h15, [x21]"),
        (0x7C37_02AF, "ldfadd h23, h15, [x21]"),
        (0x7C37_42AF, "ldfmax h23, h15, [x21]"),
        (0x7C37_52AF, "ldfmin h23, h15, [x21]"),
        (0x7C37_62AF, "ldfmaxnm h23, h15, [x21]"),
        (0x7C37_72AF, "ldfminnm h23, h15, [x21]"),
        (0x7C77_02AF, "ldfaddl h23, h15, [x21]"),
        (0x7C77_42AF, "ldfmaxl h23, h15, [x21]"),
        (0x7C77_52AF, "ldfminl h23, h15, [x21]"),
        (0x7C77_62AF, "ldfmaxnml h23, h15, [x21]"),
        (0x7C77_72AF, "ldfminnml h23, h15, [x21]"),
        (0x7CB7_02AF, "ldfadda h23, h15, [x21]"),
        (0x7CB7_42AF, "ldfmaxa h23, h15, [x21]"),
        (0x7CB7_52AF, "ldfmina h23, h15, [x21]"),
        (0x7CB7_62AF, "ldfmaxnma h23, h15, [x21]"),
        (0x7CB7_72AF, "ldfminnma h23, h15, [x21]"),
        (0x7CF7_02AF, "ldfaddal h23, h15, [x21]"),
        (0x7CF7_42AF, "ldfmaxal h23, h15, [x21]"),
        (0x7CF7_52AF, "ldfminal h23, h15, [x21]"),
        (0x7CF7_62AF, "ldfmaxnmal h23, h15, [x21]"),
        (0x7CF7_72AF, "ldfminnmal h23, h15, [x21]"),
        (0xBC37_02AF, "ldfadd s23, s15, [x21]"),
        (0xBC37_42AF, "ldfmax s23, s15, [x21]"),
        (0xBC37_52AF, "ldfmin s23, s15, [x21]"),
        (0xBC37_62AF, "ldfmaxnm s23, s15, [x21]"),
        (0xBC37_72AF, "ldfminnm s23, s15, [x21]"),
        (0xBC77_02AF, "ldfaddl s23, s15, [x21]"),
        (0xBC77_42AF, "ldfmaxl s23, s15, [x21]"),
        (0xBC77_52AF, "ldfminl s23, s15, [x21]"),
        (0xBC77_62AF, "ldfmaxnml s23, s15, [x21]"),
        (0xBC77_72AF, "ldfminnml s23, s15, [x21]"),
        (0xBCB7_02AF, "ldfadda s23, s15, [x21]"),
        (0xBCB7_42AF, "ldfmaxa s23, s15, [x21]"),
        (0xBCB7_52AF, "ldfmina s23, s15, [x21]"),
        (0xBCB7_62AF, "ldfmaxnma s23, s15, [x21]"),
        (0xBCB7_72AF, "ldfminnma s23, s15, [x21]"),
        (0xBCF7_02AF, "ldfaddal s23, s15, [x21]"),
        (0xBCF7_42AF, "ldfmaxal s23, s15, [x21]"),
        (0xBCF7_52AF, "ldfminal s23, s15, [x21]"),
        (0xBCF7_62AF, "ldfmaxnmal s23, s15, [x21]"),
        (0xBCF7_72AF, "ldfminnmal s23, s15, [x21]"),
        (0xFC37_02AF, "ldfadd d23, d15, [x21]"),
        (0xFC37_42AF, "ldfmax d23, d15, [x21]"),
        (0xFC37_52AF, "ldfmin d23, d15, [x21]"),
        (0xFC37_62AF, "ldfmaxnm d23, d15, [x21]"),
        (0xFC37_72AF, "ldfminnm d23, d15, [x21]"),
        (0xFC77_02AF, "ldfaddl d23, d15, [x21]"),
        (0xFC77_42AF, "ldfmaxl d23, d15, [x21]"),
        (0xFC77_52AF, "ldfminl d23, d15, [x21]"),
        (0xFC77_62AF, "ldfmaxnml d23, d15, [x21]"),
        (0xFC77_72AF, "ldfminnml d23, d15, [x21]"),
        (0xFCB7_02AF, "ldfadda d23, d15, [x21]"),
        (0xFCB7_42AF, "ldfmaxa d23, d15, [x21]"),
        (0xFCB7_52AF, "ldfmina d23, d15, [x21]"),
        (0xFCB7_62AF, "ldfmaxnma d23, d15, [x21]"),
        (0xFCB7_72AF, "ldfminnma d23, d15, [x21]"),
        (0xFCF7_02AF, "ldfaddal d23, d15, [x21]"),
        (0xFCF7_42AF, "ldfmaxal d23, d15, [x21]"),
        (0xFCF7_52AF, "ldfminal d23, d15, [x21]"),
        (0xFCF7_62AF, "ldfmaxnmal d23, d15, [x21]"),
        (0xFCF7_72AF, "ldfminnmal d23, d15, [x21]"),
    ]

    static let storeForms: [(word: UInt32, text: String)] = [
        (0x3C38_80FF, "stbfadd h24, [x7]"),
        (0x3C38_C0FF, "stbfmax h24, [x7]"),
        (0x3C38_D0FF, "stbfmin h24, [x7]"),
        (0x3C38_E0FF, "stbfmaxnm h24, [x7]"),
        (0x3C38_F0FF, "stbfminnm h24, [x7]"),
        (0x3C78_80FF, "stbfaddl h24, [x7]"),
        (0x3C78_C0FF, "stbfmaxl h24, [x7]"),
        (0x3C78_D0FF, "stbfminl h24, [x7]"),
        (0x3C78_E0FF, "stbfmaxnml h24, [x7]"),
        (0x3C78_F0FF, "stbfminnml h24, [x7]"),
        (0x7C38_80FF, "stfadd h24, [x7]"),
        (0x7C38_C0FF, "stfmax h24, [x7]"),
        (0x7C38_D0FF, "stfmin h24, [x7]"),
        (0x7C38_E0FF, "stfmaxnm h24, [x7]"),
        (0x7C38_F0FF, "stfminnm h24, [x7]"),
        (0x7C78_80FF, "stfaddl h24, [x7]"),
        (0x7C78_C0FF, "stfmaxl h24, [x7]"),
        (0x7C78_D0FF, "stfminl h24, [x7]"),
        (0x7C78_E0FF, "stfmaxnml h24, [x7]"),
        (0x7C78_F0FF, "stfminnml h24, [x7]"),
        (0xBC38_80FF, "stfadd s24, [x7]"),
        (0xBC38_C0FF, "stfmax s24, [x7]"),
        (0xBC38_D0FF, "stfmin s24, [x7]"),
        (0xBC38_E0FF, "stfmaxnm s24, [x7]"),
        (0xBC38_F0FF, "stfminnm s24, [x7]"),
        (0xBC78_80FF, "stfaddl s24, [x7]"),
        (0xBC78_C0FF, "stfmaxl s24, [x7]"),
        (0xBC78_D0FF, "stfminl s24, [x7]"),
        (0xBC78_E0FF, "stfmaxnml s24, [x7]"),
        (0xBC78_F0FF, "stfminnml s24, [x7]"),
        (0xFC38_80FF, "stfadd d24, [x7]"),
        (0xFC38_C0FF, "stfmax d24, [x7]"),
        (0xFC38_D0FF, "stfmin d24, [x7]"),
        (0xFC38_E0FF, "stfmaxnm d24, [x7]"),
        (0xFC38_F0FF, "stfminnm d24, [x7]"),
        (0xFC78_80FF, "stfaddl d24, [x7]"),
        (0xFC78_C0FF, "stfmaxl d24, [x7]"),
        (0xFC78_D0FF, "stfminl d24, [x7]"),
        (0xFC78_E0FF, "stfmaxnml d24, [x7]"),
        (0xFC78_F0FF, "stfminnml d24, [x7]"),
    ]

    @Test func everyLoadFormDecodesToItsHarvestedText() {
        for row in Self.loadForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
            #expect(d.memoryAccess == .atomic)
            #expect(d.flagEffect == .none)
            #expect(d.branchClass == .none)
            #expect(d.operands.count == 3)
        }
        #expect(Self.loadForms.count == 80)
    }

    @Test func everyStoreFormDecodesToItsHarvestedText() {
        for row in Self.storeForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
            #expect(d.memoryAccess == .atomic)
            #expect(d.flagEffect == .none)
            #expect(d.branchClass == .none)
            #expect(d.operands.count == 2)
        }
        #expect(Self.storeForms.count == 40)
    }

    @Test func loadFormsReadTheOperandAndBaseAndWriteTheDestination() {
        let d = decode(0x3C37_02AF)
        #expect(d.semanticReads.contains(.simd(23)))
        #expect(d.semanticReads.contains(.x(21)))
        #expect(d.semanticWrites.contains(.simd(15)))
        #expect(!d.semanticWrites.contains(.simd(23)))
    }

    @Test func storeFormsReadTheOperandAndBaseAndWriteNothing() {
        let d = decode(0x3C38_80FF)
        #expect(d.semanticReads.contains(.simd(24)))
        #expect(d.semanticReads.contains(.x(7)))
        #expect(d.semanticWrites == .empty)
    }

    @Test func acquireAndReleaseFollowTheAAndRBits() {
        #expect(decode(0x7C37_02AF).memoryOrdering == [])
        #expect(decode(0x7CB7_02AF).memoryOrdering == [.acquire])
        #expect(decode(0x7C77_02AF).memoryOrdering == [.release])
        #expect(decode(0x7CF7_02AF).memoryOrdering == [.acquire, .release])
        #expect(decode(0x7C38_80FF).memoryOrdering == [])
        #expect(decode(0x7C78_80FF).memoryOrdering == [.release])
    }

    @Test func baseRegister31RendersAsStackPointer() {
        #expect(decode(0x7C20_83FF).text == "stfadd h0, [sp]")
        #expect(decode(0x7C37_03EF).text == "ldfadd h23, h15, [sp]")
    }

    @Test func unallocatedOperationCodesAreUndefined() {
        for opc: UInt32 in [0b001, 0b010, 0b011] {
            #expect(decode(0x7C37_02AF | (opc << 12)).isUndefined, "opc \(opc)")
        }
    }

    @Test func storeFormsRequireNoAcquireAndAZeroRegisterTarget() {
        #expect(decode(0x7CB8_80FF).isUndefined)
        #expect(decode(0x7C38_80FE).isUndefined)
    }

    @Test func everyRecordPassesTheSemanticChecker() {
        for row in Self.loadForms + Self.storeForms {
            #expect(SIMDFPSemanticChecker.verify(decode(row.word)) == nil,
                    "0x\(String(row.word, radix: 16))")
        }
    }

    @Test func maskDerivationNeedsAMemoryOperand() {
        let bare = Instruction(mnemonic: .ldfadd, category: .simdAndFP)
        #expect(SIMDFPSemanticAttributes.expectedReadMask(for: bare) == nil)
        #expect(SIMDFPSemanticAttributes.expectedWriteMask(for: bare) == nil)
    }
}

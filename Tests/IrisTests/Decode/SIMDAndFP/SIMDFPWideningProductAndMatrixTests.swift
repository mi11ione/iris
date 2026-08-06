// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

private func decode(_ encoding: UInt32) -> Instruction {
    Iris.decode(encoding, at: 0)
}

/// Validates the FEAT_FHM widening half-precision products in both their
/// three-same and by-element forms, and the FMMLA / FDOT rows of the
/// three-register-extension and by-element groups.
@Suite("SIMD/FP / FEAT_FHM widening products, FMMLA and FDOT")
struct SIMDFPWideningProductAndMatrixTests {
    static let threeSameForms: [(word: UInt32, text: String)] = [
        (0x0E22_EC20, "fmlal v0.2s, v1.2h, v2.2h"),
        (0x0E3F_EFDD, "fmlal v29.2s, v30.2h, v31.2h"),
        (0x0EA2_EC20, "fmlsl v0.2s, v1.2h, v2.2h"),
        (0x0EBF_EFDD, "fmlsl v29.2s, v30.2h, v31.2h"),
        (0x2E22_CC20, "fmlal2 v0.2s, v1.2h, v2.2h"),
        (0x2E3F_CFDD, "fmlal2 v29.2s, v30.2h, v31.2h"),
        (0x2EA2_CC20, "fmlsl2 v0.2s, v1.2h, v2.2h"),
        (0x2EBF_CFDD, "fmlsl2 v29.2s, v30.2h, v31.2h"),
        (0x4E22_EC20, "fmlal v0.4s, v1.4h, v2.4h"),
        (0x4E3F_EFDD, "fmlal v29.4s, v30.4h, v31.4h"),
        (0x4EA2_EC20, "fmlsl v0.4s, v1.4h, v2.4h"),
        (0x4EBF_EFDD, "fmlsl v29.4s, v30.4h, v31.4h"),
        (0x6E22_CC20, "fmlal2 v0.4s, v1.4h, v2.4h"),
        (0x6E3F_CFDD, "fmlal2 v29.4s, v30.4h, v31.4h"),
        (0x6EA2_CC20, "fmlsl2 v0.4s, v1.4h, v2.4h"),
        (0x6EBF_CFDD, "fmlsl2 v29.4s, v30.4h, v31.4h"),
    ]

    static let byElementForms: [(word: UInt32, text: String)] = [
        (0x0F82_0020, "fmlal v0.2s, v1.2h, v2.h[0]"),
        (0x0F82_0820, "fmlal v0.2s, v1.2h, v2.h[4]"),
        (0x0F82_4020, "fmlsl v0.2s, v1.2h, v2.h[0]"),
        (0x0F82_4820, "fmlsl v0.2s, v1.2h, v2.h[4]"),
        (0x0F8F_02E9, "fmlal v9.2s, v23.2h, v15.h[0]"),
        (0x0F8F_0AE9, "fmlal v9.2s, v23.2h, v15.h[4]"),
        (0x0F8F_42E9, "fmlsl v9.2s, v23.2h, v15.h[0]"),
        (0x0F8F_4AE9, "fmlsl v9.2s, v23.2h, v15.h[4]"),
        (0x0F92_0020, "fmlal v0.2s, v1.2h, v2.h[1]"),
        (0x0F92_0820, "fmlal v0.2s, v1.2h, v2.h[5]"),
        (0x0F92_4020, "fmlsl v0.2s, v1.2h, v2.h[1]"),
        (0x0F92_4820, "fmlsl v0.2s, v1.2h, v2.h[5]"),
        (0x0F9F_02E9, "fmlal v9.2s, v23.2h, v15.h[1]"),
        (0x0F9F_0AE9, "fmlal v9.2s, v23.2h, v15.h[5]"),
        (0x0F9F_42E9, "fmlsl v9.2s, v23.2h, v15.h[1]"),
        (0x0F9F_4AE9, "fmlsl v9.2s, v23.2h, v15.h[5]"),
        (0x0FA2_0020, "fmlal v0.2s, v1.2h, v2.h[2]"),
        (0x0FA2_0820, "fmlal v0.2s, v1.2h, v2.h[6]"),
        (0x0FA2_4020, "fmlsl v0.2s, v1.2h, v2.h[2]"),
        (0x0FA2_4820, "fmlsl v0.2s, v1.2h, v2.h[6]"),
        (0x0FAF_02E9, "fmlal v9.2s, v23.2h, v15.h[2]"),
        (0x0FAF_0AE9, "fmlal v9.2s, v23.2h, v15.h[6]"),
        (0x0FAF_42E9, "fmlsl v9.2s, v23.2h, v15.h[2]"),
        (0x0FAF_4AE9, "fmlsl v9.2s, v23.2h, v15.h[6]"),
        (0x0FB2_0020, "fmlal v0.2s, v1.2h, v2.h[3]"),
        (0x0FB2_0820, "fmlal v0.2s, v1.2h, v2.h[7]"),
        (0x0FB2_4020, "fmlsl v0.2s, v1.2h, v2.h[3]"),
        (0x0FB2_4820, "fmlsl v0.2s, v1.2h, v2.h[7]"),
        (0x0FBF_02E9, "fmlal v9.2s, v23.2h, v15.h[3]"),
        (0x0FBF_0AE9, "fmlal v9.2s, v23.2h, v15.h[7]"),
        (0x0FBF_42E9, "fmlsl v9.2s, v23.2h, v15.h[3]"),
        (0x0FBF_4AE9, "fmlsl v9.2s, v23.2h, v15.h[7]"),
        (0x2F82_8020, "fmlal2 v0.2s, v1.2h, v2.h[0]"),
        (0x2F82_8820, "fmlal2 v0.2s, v1.2h, v2.h[4]"),
        (0x2F82_C020, "fmlsl2 v0.2s, v1.2h, v2.h[0]"),
        (0x2F82_C820, "fmlsl2 v0.2s, v1.2h, v2.h[4]"),
        (0x2F8F_82E9, "fmlal2 v9.2s, v23.2h, v15.h[0]"),
        (0x2F8F_8AE9, "fmlal2 v9.2s, v23.2h, v15.h[4]"),
        (0x2F8F_C2E9, "fmlsl2 v9.2s, v23.2h, v15.h[0]"),
        (0x2F8F_CAE9, "fmlsl2 v9.2s, v23.2h, v15.h[4]"),
        (0x2F92_8020, "fmlal2 v0.2s, v1.2h, v2.h[1]"),
        (0x2F92_8820, "fmlal2 v0.2s, v1.2h, v2.h[5]"),
        (0x2F92_C020, "fmlsl2 v0.2s, v1.2h, v2.h[1]"),
        (0x2F92_C820, "fmlsl2 v0.2s, v1.2h, v2.h[5]"),
        (0x2F9F_82E9, "fmlal2 v9.2s, v23.2h, v15.h[1]"),
        (0x2F9F_8AE9, "fmlal2 v9.2s, v23.2h, v15.h[5]"),
        (0x2F9F_C2E9, "fmlsl2 v9.2s, v23.2h, v15.h[1]"),
        (0x2F9F_CAE9, "fmlsl2 v9.2s, v23.2h, v15.h[5]"),
        (0x2FA2_8020, "fmlal2 v0.2s, v1.2h, v2.h[2]"),
        (0x2FA2_8820, "fmlal2 v0.2s, v1.2h, v2.h[6]"),
        (0x2FA2_C020, "fmlsl2 v0.2s, v1.2h, v2.h[2]"),
        (0x2FA2_C820, "fmlsl2 v0.2s, v1.2h, v2.h[6]"),
        (0x2FAF_82E9, "fmlal2 v9.2s, v23.2h, v15.h[2]"),
        (0x2FAF_8AE9, "fmlal2 v9.2s, v23.2h, v15.h[6]"),
        (0x2FAF_C2E9, "fmlsl2 v9.2s, v23.2h, v15.h[2]"),
        (0x2FAF_CAE9, "fmlsl2 v9.2s, v23.2h, v15.h[6]"),
        (0x2FB2_8020, "fmlal2 v0.2s, v1.2h, v2.h[3]"),
        (0x2FB2_8820, "fmlal2 v0.2s, v1.2h, v2.h[7]"),
        (0x2FB2_C020, "fmlsl2 v0.2s, v1.2h, v2.h[3]"),
        (0x2FB2_C820, "fmlsl2 v0.2s, v1.2h, v2.h[7]"),
        (0x2FBF_82E9, "fmlal2 v9.2s, v23.2h, v15.h[3]"),
        (0x2FBF_8AE9, "fmlal2 v9.2s, v23.2h, v15.h[7]"),
        (0x2FBF_C2E9, "fmlsl2 v9.2s, v23.2h, v15.h[3]"),
        (0x2FBF_CAE9, "fmlsl2 v9.2s, v23.2h, v15.h[7]"),
        (0x4F82_0020, "fmlal v0.4s, v1.4h, v2.h[0]"),
        (0x4F82_0820, "fmlal v0.4s, v1.4h, v2.h[4]"),
        (0x4F82_4020, "fmlsl v0.4s, v1.4h, v2.h[0]"),
        (0x4F82_4820, "fmlsl v0.4s, v1.4h, v2.h[4]"),
        (0x4F8F_02E9, "fmlal v9.4s, v23.4h, v15.h[0]"),
        (0x4F8F_0AE9, "fmlal v9.4s, v23.4h, v15.h[4]"),
        (0x4F8F_42E9, "fmlsl v9.4s, v23.4h, v15.h[0]"),
        (0x4F8F_4AE9, "fmlsl v9.4s, v23.4h, v15.h[4]"),
        (0x4F92_0020, "fmlal v0.4s, v1.4h, v2.h[1]"),
        (0x4F92_0820, "fmlal v0.4s, v1.4h, v2.h[5]"),
        (0x4F92_4020, "fmlsl v0.4s, v1.4h, v2.h[1]"),
        (0x4F92_4820, "fmlsl v0.4s, v1.4h, v2.h[5]"),
        (0x4F9F_02E9, "fmlal v9.4s, v23.4h, v15.h[1]"),
        (0x4F9F_0AE9, "fmlal v9.4s, v23.4h, v15.h[5]"),
        (0x4F9F_42E9, "fmlsl v9.4s, v23.4h, v15.h[1]"),
        (0x4F9F_4AE9, "fmlsl v9.4s, v23.4h, v15.h[5]"),
        (0x4FA2_0020, "fmlal v0.4s, v1.4h, v2.h[2]"),
        (0x4FA2_0820, "fmlal v0.4s, v1.4h, v2.h[6]"),
        (0x4FA2_4020, "fmlsl v0.4s, v1.4h, v2.h[2]"),
        (0x4FA2_4820, "fmlsl v0.4s, v1.4h, v2.h[6]"),
        (0x4FAF_02E9, "fmlal v9.4s, v23.4h, v15.h[2]"),
        (0x4FAF_0AE9, "fmlal v9.4s, v23.4h, v15.h[6]"),
        (0x4FAF_42E9, "fmlsl v9.4s, v23.4h, v15.h[2]"),
        (0x4FAF_4AE9, "fmlsl v9.4s, v23.4h, v15.h[6]"),
        (0x4FB2_0020, "fmlal v0.4s, v1.4h, v2.h[3]"),
        (0x4FB2_0820, "fmlal v0.4s, v1.4h, v2.h[7]"),
        (0x4FB2_4020, "fmlsl v0.4s, v1.4h, v2.h[3]"),
        (0x4FB2_4820, "fmlsl v0.4s, v1.4h, v2.h[7]"),
        (0x4FBF_02E9, "fmlal v9.4s, v23.4h, v15.h[3]"),
        (0x4FBF_0AE9, "fmlal v9.4s, v23.4h, v15.h[7]"),
        (0x4FBF_42E9, "fmlsl v9.4s, v23.4h, v15.h[3]"),
        (0x4FBF_4AE9, "fmlsl v9.4s, v23.4h, v15.h[7]"),
        (0x6F82_8020, "fmlal2 v0.4s, v1.4h, v2.h[0]"),
        (0x6F82_8820, "fmlal2 v0.4s, v1.4h, v2.h[4]"),
        (0x6F82_C020, "fmlsl2 v0.4s, v1.4h, v2.h[0]"),
        (0x6F82_C820, "fmlsl2 v0.4s, v1.4h, v2.h[4]"),
        (0x6F8F_82E9, "fmlal2 v9.4s, v23.4h, v15.h[0]"),
        (0x6F8F_8AE9, "fmlal2 v9.4s, v23.4h, v15.h[4]"),
        (0x6F8F_C2E9, "fmlsl2 v9.4s, v23.4h, v15.h[0]"),
        (0x6F8F_CAE9, "fmlsl2 v9.4s, v23.4h, v15.h[4]"),
        (0x6F92_8020, "fmlal2 v0.4s, v1.4h, v2.h[1]"),
        (0x6F92_8820, "fmlal2 v0.4s, v1.4h, v2.h[5]"),
        (0x6F92_C020, "fmlsl2 v0.4s, v1.4h, v2.h[1]"),
        (0x6F92_C820, "fmlsl2 v0.4s, v1.4h, v2.h[5]"),
        (0x6F9F_82E9, "fmlal2 v9.4s, v23.4h, v15.h[1]"),
        (0x6F9F_8AE9, "fmlal2 v9.4s, v23.4h, v15.h[5]"),
        (0x6F9F_C2E9, "fmlsl2 v9.4s, v23.4h, v15.h[1]"),
        (0x6F9F_CAE9, "fmlsl2 v9.4s, v23.4h, v15.h[5]"),
        (0x6FA2_8020, "fmlal2 v0.4s, v1.4h, v2.h[2]"),
        (0x6FA2_8820, "fmlal2 v0.4s, v1.4h, v2.h[6]"),
        (0x6FA2_C020, "fmlsl2 v0.4s, v1.4h, v2.h[2]"),
        (0x6FA2_C820, "fmlsl2 v0.4s, v1.4h, v2.h[6]"),
        (0x6FAF_82E9, "fmlal2 v9.4s, v23.4h, v15.h[2]"),
        (0x6FAF_8AE9, "fmlal2 v9.4s, v23.4h, v15.h[6]"),
        (0x6FAF_C2E9, "fmlsl2 v9.4s, v23.4h, v15.h[2]"),
        (0x6FAF_CAE9, "fmlsl2 v9.4s, v23.4h, v15.h[6]"),
        (0x6FB2_8020, "fmlal2 v0.4s, v1.4h, v2.h[3]"),
        (0x6FB2_8820, "fmlal2 v0.4s, v1.4h, v2.h[7]"),
        (0x6FB2_C020, "fmlsl2 v0.4s, v1.4h, v2.h[3]"),
        (0x6FB2_C820, "fmlsl2 v0.4s, v1.4h, v2.h[7]"),
        (0x6FBF_82E9, "fmlal2 v9.4s, v23.4h, v15.h[3]"),
        (0x6FBF_8AE9, "fmlal2 v9.4s, v23.4h, v15.h[7]"),
        (0x6FBF_C2E9, "fmlsl2 v9.4s, v23.4h, v15.h[3]"),
        (0x6FBF_CAE9, "fmlsl2 v9.4s, v23.4h, v15.h[7]"),
    ]

    static let byElementDotForms: [(word: UInt32, text: String)] = [
        (0x0F42_9020, "fdot v0.2s, v1.4h, v2.2h[0]"),
        (0x0F42_9820, "fdot v0.2s, v1.4h, v2.2h[2]"),
        (0x0F52_91A9, "fdot v9.2s, v13.4h, v18.2h[0]"),
        (0x0F52_99A9, "fdot v9.2s, v13.4h, v18.2h[2]"),
        (0x0F5F_93FF, "fdot v31.2s, v31.4h, v31.2h[0]"),
        (0x0F5F_9BFF, "fdot v31.2s, v31.4h, v31.2h[2]"),
        (0x0F62_9020, "fdot v0.2s, v1.4h, v2.2h[1]"),
        (0x0F62_9820, "fdot v0.2s, v1.4h, v2.2h[3]"),
        (0x0F72_91A9, "fdot v9.2s, v13.4h, v18.2h[1]"),
        (0x0F72_99A9, "fdot v9.2s, v13.4h, v18.2h[3]"),
        (0x0F7F_93FF, "fdot v31.2s, v31.4h, v31.2h[1]"),
        (0x0F7F_9BFF, "fdot v31.2s, v31.4h, v31.2h[3]"),
        (0x4F42_9020, "fdot v0.4s, v1.8h, v2.2h[0]"),
        (0x4F42_9820, "fdot v0.4s, v1.8h, v2.2h[2]"),
        (0x4F52_91A9, "fdot v9.4s, v13.8h, v18.2h[0]"),
        (0x4F52_99A9, "fdot v9.4s, v13.8h, v18.2h[2]"),
        (0x4F5F_93FF, "fdot v31.4s, v31.8h, v31.2h[0]"),
        (0x4F5F_9BFF, "fdot v31.4s, v31.8h, v31.2h[2]"),
        (0x4F62_9020, "fdot v0.4s, v1.8h, v2.2h[1]"),
        (0x4F62_9820, "fdot v0.4s, v1.8h, v2.2h[3]"),
        (0x4F72_91A9, "fdot v9.4s, v13.8h, v18.2h[1]"),
        (0x4F72_99A9, "fdot v9.4s, v13.8h, v18.2h[3]"),
        (0x4F7F_93FF, "fdot v31.4s, v31.8h, v31.2h[1]"),
        (0x4F7F_9BFF, "fdot v31.4s, v31.8h, v31.2h[3]"),
    ]

    static let threeRegisterExtensionForms: [(word: UInt32, text: String)] = [
        (0x0E82_FC20, "fdot v0.2s, v1.4h, v2.4h"),
        (0x0E95_FCED, "fdot v13.2s, v7.4h, v21.4h"),
        (0x4E42_EC20, "fmmla v0.4s, v1.8h, v2.8h"),
        (0x4E55_ECED, "fmmla v13.4s, v7.8h, v21.8h"),
        (0x4E82_FC20, "fdot v0.4s, v1.8h, v2.8h"),
        (0x4E95_FCED, "fdot v13.4s, v7.8h, v21.8h"),
        (0x4EC2_EC20, "fmmla v0.8h, v1.8h, v2.8h"),
        (0x4ED5_ECED, "fmmla v13.8h, v7.8h, v21.8h"),
        (0x6E02_EC20, "fmmla v0.8h, v1.16b, v2.16b"),
        (0x6E15_ECED, "fmmla v13.8h, v7.16b, v21.16b"),
        (0x6E82_EC20, "fmmla v0.4s, v1.16b, v2.16b"),
        (0x6E95_ECED, "fmmla v13.4s, v7.16b, v21.16b"),
    ]

    @Test func threeSameWideningFormsDecodeToTheirHarvestedText() {
        for row in Self.threeSameForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
            #expect(d.category == .simdAndFP)
        }
        #expect(Self.threeSameForms.count == 16)
    }

    @Test func byElementWideningFormsDecodeToTheirHarvestedText() {
        for row in Self.byElementForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
            #expect(d.operands.count == 3)
        }
        #expect(Self.byElementForms.count == 128)
    }

    @Test func byElementDotFormsDecodeToTheirHarvestedText() {
        for row in Self.byElementDotForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
        }
        #expect(Self.byElementDotForms.count == 24)
    }

    @Test func threeRegisterExtensionFormsDecodeToTheirHarvestedText() {
        for row in Self.threeRegisterExtensionForms {
            let d = decode(row.word)
            #expect(d.text == row.text, "0x\(String(row.word, radix: 16))")
        }
        #expect(Self.threeRegisterExtensionForms.count == 12)
    }

    @Test func everyWideningFormAccumulatesIntoItsDestination() {
        for row in Self.threeSameForms + Self.byElementForms
            + Self.byElementDotForms + Self.threeRegisterExtensionForms
        {
            let d = decode(row.word)
            let destination = UInt8(row.word & 0x1F)
            #expect(d.semanticReads.contains(.simd(destination)),
                    "0x\(String(row.word, radix: 16))")
            #expect(d.semanticWrites.contains(.simd(destination)))
            #expect(d.memoryAccess == .none)
            #expect(d.memoryOrdering == [])
            #expect(d.flagEffect == .none)
            #expect(SIMDFPSemanticChecker.verify(d) == nil,
                    "0x\(String(row.word, radix: 16))")
        }
    }

    @Test func oddSizeBitsRejectTheThreeSameWideningRows() {
        #expect(decode(0x0E62_EC20).isUndefined)
        #expect(decode(0x0EE2_EC20).isUndefined)
        #expect(decode(0x2E62_CC20).isUndefined)
        #expect(decode(0x2EE2_CC20).isUndefined)
    }

    @Test func matrixMultiplyRowsRequireTheFullVectorForm() {
        for word: UInt32 in [0x0E42_EC20, 0x0EC2_EC20, 0x2E02_EC20, 0x2E82_EC20] {
            #expect(decode(word).isUndefined, "0x\(String(word, radix: 16))")
        }
    }

    @Test func fmmlaSharesTheScalableFloatingPointMnemonic() {
        #expect(decode(0x4E42_EC20).mnemonic == .fmmla)
        #expect(SIMDFPSemanticAttributes.destinationReadsItself(for: .fmmla))
    }
}

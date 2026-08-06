// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Validates the predicates gating the crypto/Apple-extensions corpus
/// selection.
@Suite("CryptoAppleExtensions / Shared predicates and bit utilities")
struct CryptoAppleExtensionsCommonTests {
    @Test func amxMagicMaskAndValueRemainFixed() {
        #expect(isAMXEncoding(0x0020_1000))
        for bit in 0 ..< 32 {
            let flipped = UInt32(0x0020_1000) ^ (1 << bit)
            #expect(isAMXEncoding(flipped) == (bit < 10),
                    "bit \(bit) disagrees with mask 0xFFFF_FC00 / base 0x0020_1000")
        }
    }

    @Test func isAMXEncodingAcceptsBaseEncoding() {
        #expect(isAMXEncoding(0x0020_1000))
    }

    @Test func isAMXEncodingAcceptsEveryDocumentedOpcodeWithVariousOperands() {
        for opcode: UInt32 in 0 ..< 32 {
            for operand: UInt32 in [0, 1, 15, 31] {
                let encoding = 0x0020_1000 | (opcode << 5) | operand
                #expect(isAMXEncoding(encoding), "rejects valid AMX 0x\(String(encoding, radix: 16))")
            }
        }
    }

    @Test func isAMXEncodingRejectsTopBitsNotMatchingBase() {
        #expect(!isAMXEncoding(0x0000_0000))
        #expect(!isAMXEncoding(0xFFFF_FFFF))
        #expect(!isAMXEncoding(0x0020_1400))
        #expect(!isAMXEncoding(0x0020_1420))
        #expect(!isAMXEncoding(0x9100_0000))
        #expect(!isAMXEncoding(0x4E28_4800))
    }

    @Test func isAESRowAcceptsAllFourOpcodes() {
        #expect(isAESRow(0x4E28_4800))
        #expect(isAESRow(0x4E28_5800))
        #expect(isAESRow(0x4E28_6800))
        #expect(isAESRow(0x4E28_7800))
    }

    @Test func isAESRowRejectsNonAESPrefixes() {
        #expect(!isAESRow(0x4F28_4800))
        #expect(!isAESRow(0x4E27_4800))
        #expect(!isAESRow(0x4E28_4000))
    }

    @Test func isSHA1OrSHA256RowAcceptsThreeRegForms() {
        #expect(isSHA1OrSHA256Row(0x5E00_0000))
        #expect(isSHA1OrSHA256Row(0x5E00_6000))
    }

    @Test func isSHA1OrSHA256RowAcceptsTwoRegForms() {
        #expect(isSHA1OrSHA256Row(0x5E28_0800))
        #expect(isSHA1OrSHA256Row(0x5E28_2800))
    }

    @Test func isSHA1OrSHA256RowRejectsNonSHAPrefixes() {
        #expect(!isSHA1OrSHA256Row(0x5F00_0000))
        #expect(!isSHA1OrSHA256Row(0x5E28_0000))
    }

    @Test func isSHA3SHA512SMRowAcceptsValidBits23To21() {
        for bits23_21: UInt32 in [0b000, 0b001, 0b010, 0b011, 0b100, 0b110] {
            let encoding = 0xCE00_0000 | (bits23_21 << 21)
            #expect(isSHA3SHA512SMRow(encoding))
        }
    }

    @Test func isSHA3SHA512SMRowRejectsReservedBits23To21() {
        for bits23_21: UInt32 in [0b101, 0b111] {
            let encoding = 0xCE00_0000 | (bits23_21 << 21)
            #expect(!isSHA3SHA512SMRow(encoding))
        }
    }

    @Test func isSHA3SHA512SMRowRejectsNon0xCETopByte() {
        #expect(!isSHA3SHA512SMRow(0xCF00_0000))
        #expect(!isSHA3SHA512SMRow(0xCD00_0000))
    }

    @Test func isCryptoEncodingUnionOfRowPredicates() {
        #expect(isCryptoEncoding(0x4E28_4800))
        #expect(isCryptoEncoding(0x5E00_0000))
        #expect(isCryptoEncoding(0xCE00_0000))
        #expect(!isCryptoEncoding(0x9100_0000))
    }

    @Test func isPACOneSourceEncodingAcceptsValidPAC() {
        #expect(isPACOneSourceEncoding(0xDAC1_0020))
        #expect(isPACOneSourceEncoding(0xDAC1_1C20))
        #expect(isPACOneSourceEncoding(0xDAC1_47E0))
    }

    @Test func isPACOneSourceEncodingRejectsWrongPrefix() {
        #expect(!isPACOneSourceEncoding(0x5AC1_0020))
        #expect(!isPACOneSourceEncoding(0xDAC0_0020))
        #expect(!isPACOneSourceEncoding(0xDAC2_0020))
        #expect(!isPACOneSourceEncoding(0xFAC1_0020))
        #expect(!isPACOneSourceEncoding(0xDAC1_4820))
    }

    @Test func isPACGAEncodingAcceptsValidPACGA() {
        #expect(isPACGAEncoding(0x9AC2_3020))
    }

    @Test func isPACGAEncodingRejectsWrongOpc6() {
        #expect(!isPACGAEncoding(0x9AC2_0020))
        #expect(!isPACGAEncoding(0x9AC2_4020))
    }

    @Test func isPACStandaloneEncodingUnionOfPACPredicates() {
        #expect(isPACStandaloneEncoding(0xDAC1_0020))
        #expect(isPACStandaloneEncoding(0x9AC2_3020))
        #expect(!isPACStandaloneEncoding(0x9100_0000))
    }

    @Test func isMTEAddSubGEncodingAcceptsADDGAndSUBG() {
        #expect(isMTEAddSubGEncoding(0x9182_0C5F))
        #expect(isMTEAddSubGEncoding(0xD182_0C5F))
    }

    @Test func isMTEAddSubGEncodingRejectsWrongPrefix() {
        #expect(!isMTEAddSubGEncoding(0x9100_0000))
    }

    @Test func isMTEDataProcessingRegisterEncodingAcceptsAllFour() {
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_0020))
        #expect(isMTEDataProcessingRegisterEncoding(0xBAC2_0020))
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_1020))
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_1420))
    }

    @Test func isMTEDataProcessingRegisterEncodingRejectsWrongPrefix() {
        #expect(!isMTEDataProcessingRegisterEncoding(0x1AC2_0020))
        #expect(!isMTEDataProcessingRegisterEncoding(0xDAC2_0020))
        #expect(!isMTEDataProcessingRegisterEncoding(0x9AC2_1820))
    }

    @Test func isMTELoadStoreEncodingAcceptsValidMTELS() {
        #expect(isMTELoadStoreEncoding(0xD920_0820))
        #expect(isMTELoadStoreEncoding(0xD920_0020))
        #expect(isMTELoadStoreEncoding(0xD9E0_0020))
    }

    @Test func isMTELoadStoreEncodingRejectsWrongPrefix() {
        #expect(!isMTELoadStoreEncoding(0xD800_0820))
        #expect(!isMTELoadStoreEncoding(0xD900_0820))
    }

    @Test func isMTEEncodingUnionOfMTEPredicates() {
        #expect(isMTEEncoding(0x9182_0C5F))
        #expect(isMTEEncoding(0x9AC2_1020))
        #expect(isMTEEncoding(0xD920_0820))
        #expect(!isMTEEncoding(0x9100_0000))
    }

    @Test func isCryptoPACMTEEncodingUnionOfAllFamilies() {
        #expect(isCryptoPACMTEEncoding(0x4E28_4820))
        #expect(isCryptoPACMTEEncoding(0xDAC1_0020))
        #expect(isCryptoPACMTEEncoding(0x9AC2_3020))
        #expect(isCryptoPACMTEEncoding(0x9182_0C5F))
        #expect(isCryptoPACMTEEncoding(0xD920_0820))
        #expect(!isCryptoPACMTEEncoding(0x9100_0000))
    }

    @Test func signExtend9PositiveZero() {
        #expect(signExtend9(0x0) == 0)
    }

    @Test func signExtend9PositiveSmall() {
        #expect(signExtend9(0x1) == 1)
        #expect(signExtend9(0xFF) == 0xFF)
    }

    @Test func signExtend9NegativeMin() {
        #expect(signExtend9(0x100) == -256)
    }

    @Test func signExtend9NegativeMax() {
        #expect(signExtend9(0x1FF) == -1)
    }

    @Test func signExtend9IgnoresBitsAboveNine() {
        #expect(signExtend9(0xFFFF_FFFF) == -1)
        #expect(signExtend9(0xFFFF_FE00) == 0)
        #expect(signExtend9(0xFFFF_FF00) == -256)
    }
}

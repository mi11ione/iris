// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

@_spi(Validation) import Iris
import Testing

/// Validates the SPI predicates and bit utilities that gate the
/// validation sweep's crypto/Apple-extensions corpus selection: AMX
/// magic mask, crypto / PAC / MTE row predicates, sign-extend helpers.
@Suite("CryptoAppleExtensions / Shared predicates and bit utilities")
struct CryptoAppleExtensionsCommonTests {
    @Test func amxMagicMaskAndValueRemainFixed() {
        // Pins the magic mask 0xFFFF_FC00 / base 0x0020_1000 through the
        // predicate: the base matches, and flipping any single bit of it
        // changes the verdict exactly for the bits the mask covers
        // (bits 10-31), while the opcode/operand bits (0-9) stay free.
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
        // Adjacent reserved space (genter / gexit / sdsb at 0x00201400+):
        #expect(!isAMXEncoding(0x0020_1400))
        #expect(!isAMXEncoding(0x0020_1420))
        // Random non-AMX:
        #expect(!isAMXEncoding(0x9100_0000)) // ADD imm
        #expect(!isAMXEncoding(0x4E28_4800)) // AESE base
    }

    @Test func isAESRowAcceptsAllFourOpcodes() {
        #expect(isAESRow(0x4E28_4800)) // AESE base (opcode 0100)
        #expect(isAESRow(0x4E28_5800)) // AESD base (opcode 0101)
        #expect(isAESRow(0x4E28_6800)) // AESMC base (opcode 0110)
        #expect(isAESRow(0x4E28_7800)) // AESIMC base (opcode 0111)
    }

    @Test func isAESRowRejectsNonAESPrefixes() {
        #expect(!isAESRow(0x4F28_4800)) // wrong byte 1
        #expect(!isAESRow(0x4E27_4800)) // wrong bits 23:16
        #expect(!isAESRow(0x4E28_4000)) // bits[11:10] != 10
    }

    @Test func isSHA1OrSHA256RowAcceptsThreeRegForms() {
        // SHA1C base — opcode=000, bits[11:10]=00.
        #expect(isSHA1OrSHA256Row(0x5E00_0000))
        // SHA256SU1 base — opcode=110.
        #expect(isSHA1OrSHA256Row(0x5E00_6000))
    }

    @Test func isSHA1OrSHA256RowAcceptsTwoRegForms() {
        // SHA1H base — opcode4=0000.
        #expect(isSHA1OrSHA256Row(0x5E28_0800))
        // SHA256SU0 base — opcode4=0010.
        #expect(isSHA1OrSHA256Row(0x5E28_2800))
    }

    @Test func isSHA1OrSHA256RowRejectsNonSHAPrefixes() {
        #expect(!isSHA1OrSHA256Row(0x5F00_0000)) // wrong byte
        #expect(!isSHA1OrSHA256Row(0x5E28_0000)) // bits[11:10] != 10 on 2-reg
    }

    @Test func isSHA3SHA512SMRowAcceptsValidBits23To21() {
        // bits[23:21] ∈ {000, 001, 010, 011, 100, 110} → in scope.
        for bits23_21: UInt32 in [0b000, 0b001, 0b010, 0b011, 0b100, 0b110] {
            let encoding = 0xCE00_0000 | (bits23_21 << 21)
            #expect(isSHA3SHA512SMRow(encoding))
        }
    }

    @Test func isSHA3SHA512SMRowRejectsReservedBits23To21() {
        // bits[23:21] = 101 (reserved) and 111 (reserved) → out of scope.
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
        // AES, SHA, SM3/4 all classify as crypto via the umbrella predicate.
        #expect(isCryptoEncoding(0x4E28_4800)) // AESE
        #expect(isCryptoEncoding(0x5E00_0000)) // SHA1C base
        #expect(isCryptoEncoding(0xCE00_0000)) // EOR3 base
        #expect(!isCryptoEncoding(0x9100_0000)) // ADD imm — not crypto
    }

    @Test func isPACOneSourceEncodingAcceptsValidPAC() {
        // PACIA x0, x1 = 0xDAC10020.
        #expect(isPACOneSourceEncoding(0xDAC1_0020))
        // AUTDB x0, x1 = 0xDAC11C20 (opc6 = 000111).
        #expect(isPACOneSourceEncoding(0xDAC1_1C20))
        // XPACD x0 = 0xDAC147E0 (opc6 = 010001, Rn=11111).
        #expect(isPACOneSourceEncoding(0xDAC1_47E0))
    }

    @Test func isPACOneSourceEncodingRejectsWrongPrefix() {
        // sf=0 (top bit not 1):
        #expect(!isPACOneSourceEncoding(0x5AC1_0020))
        // opcode2 != 00001:
        #expect(!isPACOneSourceEncoding(0xDAC0_0020))
        #expect(!isPACOneSourceEncoding(0xDAC2_0020))
        // S != 0 (bit 29 set):
        #expect(!isPACOneSourceEncoding(0xFAC1_0020))
        // opc6 above 010001 (reserved):
        #expect(!isPACOneSourceEncoding(0xDAC1_4820))
    }

    @Test func isPACGAEncodingAcceptsValidPACGA() {
        // PACGA x0, x1, x2 = 0x9AC23020.
        #expect(isPACGAEncoding(0x9AC2_3020))
    }

    @Test func isPACGAEncodingRejectsWrongOpc6() {
        // opc6 != 001100:
        #expect(!isPACGAEncoding(0x9AC2_0020)) // opc6 = 000000
        #expect(!isPACGAEncoding(0x9AC2_4020)) // opc6 = 010000
    }

    @Test func isPACStandaloneEncodingUnionOfPACPredicates() {
        #expect(isPACStandaloneEncoding(0xDAC1_0020)) // PACIA
        #expect(isPACStandaloneEncoding(0x9AC2_3020)) // PACGA
        #expect(!isPACStandaloneEncoding(0x9100_0000)) // ADD imm
    }

    @Test func isMTEAddSubGEncodingAcceptsADDGAndSUBG() {
        // ADDG sp, x2, #32, #3 = 0x91820C5F (bit 30=0).
        #expect(isMTEAddSubGEncoding(0x9182_0C5F))
        // SUBG sp, x2, #32, #3 = 0xD1820C5F (bit 30=1).
        #expect(isMTEAddSubGEncoding(0xD182_0C5F))
    }

    @Test func isMTEAddSubGEncodingRejectsWrongPrefix() {
        #expect(!isMTEAddSubGEncoding(0x9100_0000)) // ADD imm without bit 23
    }

    @Test func isMTEDataProcessingRegisterEncodingAcceptsAllFour() {
        // SUBP x0, x1, x2 (S=0, opc6=000000).
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_0020))
        // SUBPS x0, x1, x2 (S=1, opc6=000000).
        #expect(isMTEDataProcessingRegisterEncoding(0xBAC2_0020))
        // IRG x0, x1, x2 (opc6=000100).
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_1020))
        // GMI x0, x1, x2 (opc6=000101).
        #expect(isMTEDataProcessingRegisterEncoding(0x9AC2_1420))
    }

    @Test func isMTEDataProcessingRegisterEncodingRejectsWrongPrefix() {
        // sf=0:
        #expect(!isMTEDataProcessingRegisterEncoding(0x1AC2_0020))
        // bit 30 = 1 (DPR 1-source row, not 2-source):
        #expect(!isMTEDataProcessingRegisterEncoding(0xDAC2_0020))
        // opc6 outside MTE-DPR subspace:
        #expect(!isMTEDataProcessingRegisterEncoding(0x9AC2_1820))
    }

    @Test func isMTELoadStoreEncodingAcceptsValidMTELS() {
        // STG x0, [x1] = 0xD9200820 (opc1=00, op2=10).
        #expect(isMTELoadStoreEncoding(0xD920_0820))
        // STZGM x0, [x1] = 0xD9200020 (opc1=00, op2=00, simm9=0).
        #expect(isMTELoadStoreEncoding(0xD920_0020))
        // LDGM x0, [x1] = 0xD9E00020.
        #expect(isMTELoadStoreEncoding(0xD9E0_0020))
    }

    @Test func isMTELoadStoreEncodingRejectsWrongPrefix() {
        // Wrong top byte:
        #expect(!isMTELoadStoreEncoding(0xD800_0820))
        // Bit 21 = 0 (LRCPC2, not MTE):
        #expect(!isMTELoadStoreEncoding(0xD900_0820))
    }

    @Test func isMTEEncodingUnionOfMTEPredicates() {
        #expect(isMTEEncoding(0x9182_0C5F)) // ADDG
        #expect(isMTEEncoding(0x9AC2_1020)) // IRG
        #expect(isMTEEncoding(0xD920_0820)) // STG
        #expect(!isMTEEncoding(0x9100_0000)) // ADD imm
    }

    @Test func isCryptoPACMTEEncodingUnionOfAllFamilies() {
        #expect(isCryptoPACMTEEncoding(0x4E28_4820)) // AESE
        #expect(isCryptoPACMTEEncoding(0xDAC1_0020)) // PACIA
        #expect(isCryptoPACMTEEncoding(0x9AC2_3020)) // PACGA
        #expect(isCryptoPACMTEEncoding(0x9182_0C5F)) // ADDG
        #expect(isCryptoPACMTEEncoding(0xD920_0820)) // STG
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
        // 9-bit two's-complement minimum: 0x100 → -256.
        #expect(signExtend9(0x100) == -256)
    }

    @Test func signExtend9NegativeMax() {
        // 9-bit two's-complement maximum negative: 0x1FF → -1.
        #expect(signExtend9(0x1FF) == -1)
    }

    @Test func signExtend9IgnoresBitsAboveNine() {
        // Bits beyond the 9-bit mask are dropped BEFORE sign extension.
        // 0xFFFF_FFFF & 0x1FF = 0x1FF → bit 8 set → sign-extends to -1.
        #expect(signExtend9(0xFFFF_FFFF) == -1)
        // 0xFFFF_FE00 & 0x1FF = 0x000 → bit 8 clear → zero (no sign-extend).
        #expect(signExtend9(0xFFFF_FE00) == 0)
        // 0xFFFF_FF00 & 0x1FF = 0x100 → bit 8 set → -256.
        #expect(signExtend9(0xFFFF_FF00) == -256)
    }
}

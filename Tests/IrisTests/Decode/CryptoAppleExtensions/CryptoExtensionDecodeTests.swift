// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates every documented crypto mnemonic across AES, SHA-1/256/3/512, SM3
/// and SM4.
@Suite("CryptoAppleExtensions / CryptoExtensionDecode")
struct CryptoExtensionDecodeTests {
    @Test func nonCryptoTopByteReturnsNil() {
        #expect(decode(0x9100_0000, at: 0).category != .crypto)
    }

    @Test func aeseBase() {
        let d = decode(0x4E28_4800, at: 0)
        #expect(d.mnemonic == .aese)
        #expect(d.category == .crypto)
        #expect(d.operands.count == 2)
    }

    @Test func aesdBase() {
        let d = decode(0x4E28_5800, at: 0)
        #expect(d.mnemonic == .aesd)
    }

    @Test func aesmcBase() {
        let d = decode(0x4E28_6800, at: 0)
        #expect(d.mnemonic == .aesmc)
    }

    @Test func aesimcBase() {
        let d = decode(0x4E28_7800, at: 0)
        #expect(d.mnemonic == .aesimc)
    }

    @Test func aeseIsTiedReadsBothVdAndVn() {
        let d = decode(0x4E28_4800 | 0x05 | (0x07 << 5), at: 0)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func aesmcIsNotTiedReadsOnlyVn() {
        let d = decode(0x4E28_6800 | 0x05 | (0x07 << 5), at: 0)
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
    }

    @Test func sha1su1IsVdTied() {
        let d = decode(0x5E28_18E5, at: 0)
        #expect(d.mnemonic == .sha1su1)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha256su0IsVdTied() {
        let d = decode(0x5E28_28E5, at: 0)
        #expect(d.mnemonic == .sha256su0)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha512su0IsVdTied() {
        let d = decode(0xCEC0_80E5, at: 0)
        #expect(d.mnemonic == .sha512su0)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sm4eIsVdTied() {
        let d = decode(0xCEC0_84E5, at: 0)
        #expect(d.mnemonic == .sm4e)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha512hIsQdTied() {
        let d = decode(0xCE69_80E5, at: 0)
        #expect(d.mnemonic == .sha512h)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha512h2IsQdTied() {
        let d = decode(0xCE69_84E5, at: 0)
        #expect(d.mnemonic == .sha512h2)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
    }

    @Test func rax1IsNotTied() {
        let d = decode(0xCE69_8CE5, at: 0)
        #expect(d.mnemonic == .rax1)
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sm4ekeyIsNotTied() {
        let d = decode(0xCE69_C8E5, at: 0)
        #expect(d.mnemonic == .sm4ekey)
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func aesReservedOpcodeReturnsNil() {
        #expect(decode(0x4E28_0800, at: 0).category != .crypto)
        #expect(decode(0x4E28_8800, at: 0).category != .crypto)
    }

    @Test func aesNonAESTopBitsReturnsNil() {
        #expect(decode(0x4F28_4800, at: 0).category != .crypto)
    }

    @Test func sha1cThreeReg() {
        let d = decode(0x5E00_0000, at: 0)
        #expect(d.mnemonic == .sha1c)
        #expect(d.category == .crypto)
        #expect(d.operands.count == 3)
    }

    @Test func sha1pThreeReg() {
        let d = decode(0x5E00_1000, at: 0)
        #expect(d.mnemonic == .sha1p)
    }

    @Test func sha1mThreeReg() {
        let d = decode(0x5E00_2000, at: 0)
        #expect(d.mnemonic == .sha1m)
    }

    @Test func sha1su0ThreeReg() {
        let d = decode(0x5E00_3000, at: 0)
        #expect(d.mnemonic == .sha1su0)
    }

    @Test func sha256hThreeReg() {
        let d = decode(0x5E00_4000, at: 0)
        #expect(d.mnemonic == .sha256h)
    }

    @Test func sha256h2ThreeReg() {
        let d = decode(0x5E00_5000, at: 0)
        #expect(d.mnemonic == .sha256h2)
    }

    @Test func sha256su1ThreeReg() {
        let d = decode(0x5E00_6000, at: 0)
        #expect(d.mnemonic == .sha256su1)
    }

    @Test func sha1hTwoReg() {
        let d = decode(0x5E28_0800, at: 0)
        #expect(d.mnemonic == .sha1h)
        #expect(d.operands.count == 2)
    }

    @Test func sha1su1TwoReg() {
        let d = decode(0x5E28_1800, at: 0)
        #expect(d.mnemonic == .sha1su1)
    }

    @Test func sha256su0TwoReg() {
        let d = decode(0x5E28_2800, at: 0)
        #expect(d.mnemonic == .sha256su0)
    }

    @Test func sha1ThreeRegReservedOp3ReturnsNil() {
        let d = decode(0x5E00_7000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha1TwoRegReservedOp4ReturnsNil() {
        let d = decode(0x5E28_3800, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha1Or256NonMatchingPrefixReturnsNil() {
        #expect(decode(0x5E00_0400, at: 0).category != .crypto)
        #expect(decode(0x5E28_0000, at: 0).category != .crypto)
    }

    @Test func eor3Decodes() {
        let d = decode(0xCE00_0000, at: 0)
        #expect(d.mnemonic == .eor3)
        #expect(d.operands.count == 4)
    }

    @Test func bcaxDecodes() {
        let d = decode(0xCE20_0000, at: 0)
        #expect(d.mnemonic == .bcax)
    }

    @Test func sha3FourRegBit15SetReturnsNil() {
        let d = decode(0xCE00_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sm3ss1Decodes() {
        let d = decode(0xCE40_0000, at: 0)
        #expect(d.mnemonic == .sm3ss1)
        #expect(d.operands.count == 4)
    }

    @Test func sm3tt1aDecodes() {
        let d = decode(0xCE40_8000, at: 0)
        #expect(d.mnemonic == .sm3tt1a)
        #expect(d.operands.count == 3)
    }

    @Test func sm3tt1bDecodes() {
        let d = decode(0xCE40_8400, at: 0)
        #expect(d.mnemonic == .sm3tt1b)
    }

    @Test func sm3tt2aDecodes() {
        let d = decode(0xCE40_8800, at: 0)
        #expect(d.mnemonic == .sm3tt2a)
    }

    @Test func sm3tt2bDecodes() {
        let d = decode(0xCE40_8C00, at: 0)
        #expect(d.mnemonic == .sm3tt2b)
    }

    @Test func sm3ttLaneIndexInOperand() {
        let d = decode(0xCE40_8000 | (3 << 12), at: 0)
        #expect(d.mnemonic == .sm3tt1a)
        let expectedElement: Operand = .vectorRegister(.init(
            registerIndex: 0,
            view: .element(arrangement: .s4, index: 3),
        ))
        #expect(d.operands[2] == expectedElement)
    }

    @Test func sha512hDecodes() {
        let d = decode(0xCE60_8000, at: 0)
        #expect(d.mnemonic == .sha512h)
    }

    @Test func sha512h2Decodes() {
        let d = decode(0xCE60_8400, at: 0)
        #expect(d.mnemonic == .sha512h2)
    }

    @Test func sha512su1Decodes() {
        let d = decode(0xCE60_8800, at: 0)
        #expect(d.mnemonic == .sha512su1)
    }

    @Test func rax1Decodes() {
        let d = decode(0xCE60_8C00, at: 0)
        #expect(d.mnemonic == .rax1)
    }

    @Test func sm3partw1Decodes() {
        let d = decode(0xCE60_C000, at: 0)
        #expect(d.mnemonic == .sm3partw1)
    }

    @Test func sm3partw2Decodes() {
        let d = decode(0xCE60_C400, at: 0)
        #expect(d.mnemonic == .sm3partw2)
    }

    @Test func sm4ekeyDecodes() {
        let d = decode(0xCE60_C800, at: 0)
        #expect(d.mnemonic == .sm4ekey)
    }

    @Test func threeRegReservedOp0Op1ReturnsNil() {
        let d = decode(0xCE60_CC00, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func xarDecodes() {
        let d = decode(0xCE80_0000, at: 0)
        #expect(d.mnemonic == .xar)
        #expect(d.operands.count == 4)
        #expect(d.operands[3] == .unsignedImmediate(value: 0, width: 6))
    }

    @Test func xarWithImm6Max() {
        let d = decode(0xCE80_FC00, at: 0)
        #expect(d.mnemonic == .xar)
        #expect(d.operands[3] == .unsignedImmediate(value: 63, width: 6))
    }

    @Test func sha512su0Decodes() {
        let d = decode(0xCEC0_8000, at: 0)
        #expect(d.mnemonic == .sha512su0)
    }

    @Test func sm4eDecodes() {
        let d = decode(0xCEC0_8400, at: 0)
        #expect(d.mnemonic == .sm4e)
    }

    @Test func twoRegReservedOp1ReturnsNil() {
        let d = decode(0xCEC0_8800, at: 0)
        #expect(d.category != .crypto)
        let d2 = decode(0xCEC0_8C00, at: 0)
        #expect(d2.category != .crypto)
    }

    @Test func twoRegWrongPrefixReturnsNil() {
        let d = decode(0xCEC1_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func bits23To21EqualOneOhOneReturnsNil() {
        let d = decode(0xCEA0_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func bits23To21EqualOneOneOneReturnsNil() {
        let d = decode(0xCEE0_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha3FourRegWithBit15SetReturnsNil() {
        let d = decode(0xCE00_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sm3ttWithBit14SetReturnsNil() {
        let d = decode(0xCE40_C000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func threeRegSHA512SMWithBit15ClearReturnsNil() {
        let d = decode(0xCE60_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func threeRegSHA512SMWithBits13_12NonZeroReturnsNil() {
        let d = decode(0xCE60_9000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func twoRegSHA512SM4EWithRmNonZeroReturnsNil() {
        let d = decode(0xCEC1_8000, at: 0)
        #expect(d.category != .crypto)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the crypto extension decoder for every documented
/// mnemonic across AES / SHA-1 / SHA-256 / SHA-3 / SHA-512 / SM3 /
/// SM4 row prefixes; verifies arrangement semantics (`.16B` for AES /
/// SHA-3 4-reg, `.4S` for SHA-1/256 3-reg / SM3 / SM4 / SM3PARTW,
/// `.2D` for SHA-512 / RAX1 / XAR), tied-vs-untied operand semantics,
/// SM3TT lane indices, XAR imm6, and reserved-encoding rejection.
@Suite("CryptoAppleExtensions / CryptoExtensionDecode")
struct CryptoExtensionDecodeTests {
    @Test func nonCryptoTopByteReturnsNil() {
        // Top byte not in {0x4E, 0x5E, 0xCE}.
        #expect(decode(0x9100_0000, at: 0).category != .crypto)
    }

    @Test func aeseBase() {
        // AESE v0.16b, v0.16b = 0x4E284800.
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
        // AESE Rd-tied — semanticReads includes Vd's SIMD index.
        let d = decode(0x4E28_4800 | 0x05 | (0x07 << 5), at: 0)
        // Rd = 5, Rn = 7.
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func aesmcIsNotTiedReadsOnlyVn() {
        // AESMC NOT tied — semanticReads is Vn only.
        let d = decode(0x4E28_6800 | 0x05 | (0x07 << 5), at: 0)
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
    }

    @Test func sha1su1IsVdTied() {
        // SHA1SU1 v5.4s, v7.4s — Vd-tied 2-register form; reads must
        // include both Vd (5) and Vn (7).
        let d = decode(0x5E28_18E5, at: 0)
        #expect(d.mnemonic == .sha1su1)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha256su0IsVdTied() {
        // SHA256SU0 v5.4s, v7.4s — Vd-tied.
        let d = decode(0x5E28_28E5, at: 0)
        #expect(d.mnemonic == .sha256su0)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha512su0IsVdTied() {
        // SHA512SU0 v5.2d, v7.2d — Vd-tied 2-register SHA-512 form.
        let d = decode(0xCEC0_80E5, at: 0)
        #expect(d.mnemonic == .sha512su0)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sm4eIsVdTied() {
        // SM4E v5.4s, v7.4s — Vd-tied.
        let d = decode(0xCEC0_84E5, at: 0)
        #expect(d.mnemonic == .sm4e)
        #expect(d.semanticReads.contains(.simd(5)) == true)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sha512hIsQdTied() {
        // SHA512H q5, q7, v9.2d — Qd-tied 3-register form; reads include
        // Vd (5), Vn (7), Vm (9).
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
        // RAX1 v5.2d, v7.2d, v9.2d — not tied; Vd is write-only.
        let d = decode(0xCE69_8CE5, at: 0)
        #expect(d.mnemonic == .rax1)
        // Vd (5) is written but not read.
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func sm4ekeyIsNotTied() {
        // SM4EKEY v5.4s, v7.4s, v9.4s — not tied; Vd is write-only.
        let d = decode(0xCE69_C8E5, at: 0)
        #expect(d.mnemonic == .sm4ekey)
        #expect(d.semanticReads.contains(.simd(5)) == false)
        #expect(d.semanticReads.contains(.simd(7)) == true)
        #expect(d.semanticReads.contains(.simd(9)) == true)
        #expect(d.semanticWrites.contains(.simd(5)) == true)
    }

    @Test func aesReservedOpcodeReturnsNil() {
        // AES opcode bits[15:12] ∈ {0000..0011, 1000..1111} are reserved.
        // 0x4E280800 → opcode = 0b0000 (reserved).
        #expect(decode(0x4E28_0800, at: 0).category != .crypto)
        // 0x4E288800 → opcode = 0b1000 (reserved).
        #expect(decode(0x4E28_8800, at: 0).category != .crypto)
    }

    @Test func aesNonAESTopBitsReturnsNil() {
        // 0x4F prefix — different bits[31:24].
        #expect(decode(0x4F28_4800, at: 0).category != .crypto)
    }

    @Test func sha1cThreeReg() {
        // SHA1C q0, s0, v0.4s = 0x5E000000 (op3=000).
        let d = decode(0x5E00_0000, at: 0)
        #expect(d.mnemonic == .sha1c)
        #expect(d.category == .crypto)
        #expect(d.operands.count == 3)
    }

    @Test func sha1pThreeReg() {
        // SHA1P — op3 = 001 → bits[14:12] = 001.
        let d = decode(0x5E00_1000, at: 0)
        #expect(d.mnemonic == .sha1p)
    }

    @Test func sha1mThreeReg() {
        // SHA1M — op3 = 010.
        let d = decode(0x5E00_2000, at: 0)
        #expect(d.mnemonic == .sha1m)
    }

    @Test func sha1su0ThreeReg() {
        // SHA1SU0 — op3 = 011, Vd.4S.
        let d = decode(0x5E00_3000, at: 0)
        #expect(d.mnemonic == .sha1su0)
    }

    @Test func sha256hThreeReg() {
        // SHA256H — op3 = 100, Qd-tied.
        let d = decode(0x5E00_4000, at: 0)
        #expect(d.mnemonic == .sha256h)
    }

    @Test func sha256h2ThreeReg() {
        // SHA256H2 — op3 = 101.
        let d = decode(0x5E00_5000, at: 0)
        #expect(d.mnemonic == .sha256h2)
    }

    @Test func sha256su1ThreeReg() {
        // SHA256SU1 — op3 = 110.
        let d = decode(0x5E00_6000, at: 0)
        #expect(d.mnemonic == .sha256su1)
    }

    @Test func sha1hTwoReg() {
        // SHA1H — op4 = 0000. Operands are scalar Sd/Sn (not vector).
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
        // op3 = 111 (reserved).
        let d = decode(0x5E00_7000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha1TwoRegReservedOp4ReturnsNil() {
        // op4 = 0011 (reserved in 2-reg form).
        let d = decode(0x5E28_3800, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha1Or256NonMatchingPrefixReturnsNil() {
        // bits[11:10] != 00 for 3-reg form:
        #expect(decode(0x5E00_0400, at: 0).category != .crypto)
        // bits[11:10] != 10 for 2-reg form:
        #expect(decode(0x5E28_0000, at: 0).category != .crypto)
    }

    @Test func eor3Decodes() {
        // EOR3 v0.16b, v0.16b, v0.16b, v0.16b = 0xCE000000.
        let d = decode(0xCE00_0000, at: 0)
        #expect(d.mnemonic == .eor3)
        #expect(d.operands.count == 4)
    }

    @Test func bcaxDecodes() {
        // BCAX = bits[22:21] = 01.
        let d = decode(0xCE20_0000, at: 0)
        #expect(d.mnemonic == .bcax)
    }

    @Test func sha3FourRegBit15SetReturnsNil() {
        // bits[15]=1 with this row prefix is reserved.
        let d = decode(0xCE00_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sm3ss1Decodes() {
        // SM3SS1 v0.4s, v0.4s, v0.4s, v0.4s = 0xCE400000 (bits[22:21]=10, bit 15=0).
        let d = decode(0xCE40_0000, at: 0)
        #expect(d.mnemonic == .sm3ss1)
        #expect(d.operands.count == 4)
    }

    @Test func sm3tt1aDecodes() {
        // SM3TT1A op1=00 (bits[11:10] = 00). bit 15 = 1.
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
        // SM3TT1A with imm2 = 3 → Vm.S[3].
        let d = decode(0xCE40_8000 | (3 << 12), at: 0)
        #expect(d.mnemonic == .sm3tt1a)
        // Operand[2] is the element-view at index 3.
        let expectedElement: Operand = .vectorRegister(.init(
            registerIndex: 0,
            view: .element(arrangement: .s4, index: 3),
        ))
        #expect(d.operands[2] == expectedElement)
    }

    @Test func sha512hDecodes() {
        // SHA512H q0, q0, v0.2d = 0xCE608000 (op0=0, op1=00).
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
        // RAX1 — same row as SHA512SU1, op0=0, op1=11.
        let d = decode(0xCE60_8C00, at: 0)
        #expect(d.mnemonic == .rax1)
    }

    @Test func sm3partw1Decodes() {
        // SM3PARTW1 — op0=1, op1=00.
        let d = decode(0xCE60_C000, at: 0)
        #expect(d.mnemonic == .sm3partw1)
    }

    @Test func sm3partw2Decodes() {
        // SM3PARTW2 — op0=1, op1=01.
        let d = decode(0xCE60_C400, at: 0)
        #expect(d.mnemonic == .sm3partw2)
    }

    @Test func sm4ekeyDecodes() {
        // SM4EKEY — op0=1, op1=10.
        let d = decode(0xCE60_C800, at: 0)
        #expect(d.mnemonic == .sm4ekey)
    }

    @Test func threeRegReservedOp0Op1ReturnsNil() {
        // op0=1, op1=11 is reserved.
        let d = decode(0xCE60_CC00, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func xarDecodes() {
        // XAR v0.2d, v0.2d, v0.2d, #0 = 0xCE800000.
        let d = decode(0xCE80_0000, at: 0)
        #expect(d.mnemonic == .xar)
        #expect(d.operands.count == 4)
        // imm6 at operand[3].
        #expect(d.operands[3] == .unsignedImmediate(value: 0, width: 6))
    }

    @Test func xarWithImm6Max() {
        // XAR with imm6 = 0x3F.
        let d = decode(0xCE80_FC00, at: 0)
        #expect(d.mnemonic == .xar)
        #expect(d.operands[3] == .unsignedImmediate(value: 63, width: 6))
    }

    @Test func sha512su0Decodes() {
        // SHA512SU0 = 0xCEC08000 (op1=00).
        let d = decode(0xCEC0_8000, at: 0)
        #expect(d.mnemonic == .sha512su0)
    }

    @Test func sm4eDecodes() {
        // SM4E = 0xCEC08400 (op1=01).
        let d = decode(0xCEC0_8400, at: 0)
        #expect(d.mnemonic == .sm4e)
    }

    @Test func twoRegReservedOp1ReturnsNil() {
        // op1=10 in the 2-reg row is reserved.
        let d = decode(0xCEC0_8800, at: 0)
        #expect(d.category != .crypto)
        // op1=11 reserved.
        let d2 = decode(0xCEC0_8C00, at: 0)
        #expect(d2.category != .crypto)
    }

    @Test func twoRegWrongPrefixReturnsNil() {
        // Wrong Rm = 1 instead of 0 → not 2-reg row.
        let d = decode(0xCEC1_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func bits23To21EqualOneOhOneReturnsNil() {
        // bits[23:21] = 101 → not crypto.
        let d = decode(0xCEA0_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func bits23To21EqualOneOneOneReturnsNil() {
        // bits[23:21] = 111 → not crypto.
        let d = decode(0xCEE0_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sha3FourRegWithBit15SetReturnsNil() {
        // bits[24:21] ∈ {0b0000, 0b0001} routes to decodeSHA3FourReg,
        // which requires bit 15 = 0. Encoding 0xCE00_8000 has the
        // right outer dispatch + bit 15 = 1 → inner check fails.
        let d = decode(0xCE00_8000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func sm3ttWithBit14SetReturnsNil() {
        // SM3TT routes via bits[24:21]=0b0010, bit 15 = 1, bits[14:14]=0.
        // Setting bit 14 = 1 lets bits[15:14] = 11 (reserved for this row),
        // failing the inner prefix mask.
        let d = decode(0xCE40_C000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func threeRegSHA512SMWithBit15ClearReturnsNil() {
        // 3-reg SHA512/SM3/SM4 row requires bit 15 = 1; with bits[24:21]=0b0011
        // but bit 15 = 0, the inner check fails.
        let d = decode(0xCE60_0000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func threeRegSHA512SMWithBits13_12NonZeroReturnsNil() {
        // 3-reg row requires bits[13:12] = 00. Setting bit 12 → fail.
        let d = decode(0xCE60_9000, at: 0)
        #expect(d.category != .crypto)
    }

    @Test func twoRegSHA512SM4EWithRmNonZeroReturnsNil() {
        // 2-reg row at bits[24:21]=0b0110 requires bits[20:16]=00000.
        // Setting Rm bit → fail prefix.
        let d = decode(0xCEC1_8000, at: 0)
        #expect(d.category != .crypto)
    }
}

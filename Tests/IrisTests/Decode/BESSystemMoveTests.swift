// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates MSR-register / MRS decode: the 15-bit
/// (op0LSB, op1, CRn, CRm, op2) sysreg encoding is extracted into a
/// SystemRegisterEncoding tuple, Rt at bits 4:0. MSR reads Rt + writes
/// sysreg (sysreg writes not in GP set); MRS writes Rt + reads sysreg.
@Suite("BES / MSR (register) / MRS decode")
struct BESSystemMoveTests {
    @Test func mrsTpidrEl0() {
        // 0xD53BD040 = MRS X0, TPIDR_EL0 (op0=3, op1=3, CRn=13, CRm=0, op2=2)
        let d = decode(0xD53B_D040, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)))
        #expect(d.semanticWrites.contains(.x(0)))
        #expect(d.semanticReads.mask == 0)
    }

    @Test func mrsNzcv() {
        // 0xD53B4201 = MRS X1, NZCV
        let d = decode(0xD53B_4201, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 4, crm: 2, op2: 0)))
    }

    @Test func mrsRtXzr() {
        // Rt = 31 → XZR (read sysreg, write XZR, semantically a no-op).
        let d = decode(0xD53B_D05F, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[0] == .register(.xzr()))
    }

    @Test func msrTpidrEl0() {
        // 0xD51BD040 = MSR TPIDR_EL0, X0 (L=0)
        let d = decode(0xD51B_D040, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands.count == 2)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 13, crm: 0, op2: 2)))
        #expect(d.operands[1] == .register(.x(0)))
        #expect(d.semanticReads.contains(.x(0)))
        #expect(d.semanticWrites.mask == 0)
    }

    @Test func msrRtXzr() {
        // MSR sysreg, XZR
        let d = decode(0xD51B_D05F, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[1] == .register(.xzr()))
    }

    @Test func msrOp0EqualsTwo() {
        // bit 19 = 0 → op0 = 2. Construct encoding with op0=2, op1=3, CRn=0, CRm=0, op2=0, Rt=0
        // bits 20:19 = 10 → bit 20=1, bit 19=0 → 0xD512_0000? Let's compute.
        // bits 31:22 = 1101010100, bit 21 = 0, bits 20:19 = 10, bits 18:16 = 011,
        // bits 15:12 = 0000, bits 11:8 = 0000, bits 7:5 = 000, bits 4:0 = 00000
        // = 0xD513_0000
        let d = decode(0xD513_0000, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 2, op1: 3, crn: 0, crm: 0, op2: 0)))
    }

    /// Apple/IMPDEF system registers occupy the architecturally-reserved
    /// CRn = 11 and CRn = 15 generic ranges. They carry no architectural
    /// name, so decode preserves the raw (op0, op1, CRn, CRm, op2) tuple
    /// exactly and the text layer renders the generic S-form. The whole
    /// generic MSR/MRS space (131,072 words) and the Apple CRn ∈ {11,15}
    /// range (16,384 words, Rt varied) were swept against llvm-mc 22.1.4 at
    /// the maximal BES mattr with zero divergence; these cases pin the
    /// representative IMPDEF encodings.
    @Test func mrsAppleImpdefCRn11() {
        // 0xD538B020 = MRS X0, S3_0_c11_c0_1 (op0=3, op1=0, CRn=11, CRm=0, op2=1).
        let d = decode(0xD538_B020, at: 0)
        #expect(d.mnemonic == .mrs)
        #expect(d.operands[0] == .register(.x(0)))
        #expect(d.operands[1] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 0, crn: 11, crm: 0, op2: 1)))
        #expect(d.semanticWrites.contains(.x(0)))
    }

    @Test func msrAppleImpdefCRn15() {
        // 0xD51BF3E5 = MSR S3_3_c15_c3_7, X5 (op0=3, op1=3, CRn=15, CRm=3, op2=7).
        let d = decode(0xD51B_F3E5, at: 0)
        #expect(d.mnemonic == .msr)
        #expect(d.operands[0] == .systemRegister(SystemRegisterEncoding(op0: 3, op1: 3, crn: 15, crm: 3, op2: 7)))
        #expect(d.operands[1] == .register(.x(5)))
        #expect(d.semanticReads.contains(.x(5)))
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the L13 LSE atomic class — the RMW operations
/// LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN/SWP, their
/// orderings, and the ST*-alias collapse when Rt = ZR. Checks atomic
/// classification, the (op × size × ordering) cube, and the alias rule.
@Suite("L/S LSE atomic decode")
struct LSLSEAtomicTests {
    private func decode(_ e: UInt32) -> Instruction {
        Iris.decode(e, at: 0)
    }

    @Test func ldaddByteBaseForm() {
        // 0x38200000 = ldaddb w0, w0, [x0].
        let d = decode(0x3820_0000)
        #expect(d.mnemonic == .ldaddb)
        #expect(Array(d.operands) == [
            .register(.w(0)), .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        #expect(d.memoryOrdering == [])
        // RMW reads Rs + Rn; writes Rt (the loaded original value).
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
        #expect(d.semanticWrites.mask == (UInt64(1) << 0))
    }

    @Test func ldaddWordAndDoublewordForms() {
        // 0xb8200000 = ldadd w0, w0, [x0]; 0xf8200000 = ldadd x0, x0, [x0].
        #expect(decode(0xB820_0000).mnemonic == .ldadd)
        let dword = decode(0xF820_0000)
        #expect(dword.mnemonic == .ldadd)
        #expect(dword.operands.first == .register(.x(0)))
    }

    @Test func ldsetSelectsTheRightOperation() {
        // 0xb8203000 = ldset w0, w0, [x0] — op field = 0011.
        #expect(decode(0xB820_3000).mnemonic == .ldset)
    }

    @Test func swpDecodesAndCarriesAtomicAccess() {
        // 0xf8208000 = swp x0, x0, [x0] — op field = 1000.
        let d = decode(0xF820_8000)
        #expect(d.mnemonic == .swp)
        #expect(d.memoryAccess == .atomic)
    }

    @Test func acquireSuffixForm() {
        // 0x38a00000 = ldaddab w0, w0, [x0] — A=1.
        let d = decode(0x38A0_0000)
        #expect(d.mnemonic == .ldaddab)
        #expect(d.memoryOrdering == [.acquire])
    }

    @Test func acquireReleaseSuffixForms() {
        // 0x38e00000 = ldaddalb; 0xf8e00000 = ldaddal.
        #expect(decode(0x38E0_0000).mnemonic == .ldaddalb)
        let d = decode(0xF8E0_0000)
        #expect(d.mnemonic == .ldaddal)
        #expect(d.memoryOrdering == [.acquire, .release])
    }

    @Test func zeroDestinationCollapsesToStoreAlias() {
        // 0x3820001f = staddb w0, [x0] — Rt=ZR, A=0 → ST*-alias form.
        let d = decode(0x3820_001F)
        #expect(d.mnemonic == .staddb)
        #expect(Array(d.operands) == [
            .register(.w(0)),
            .memory(MemoryOperand(base: .register(.x(0)))),
        ])
        #expect(d.memoryAccess == .atomic)
        // The alias drops Rt; nothing is written, Rs + Rn are read.
        #expect(d.semanticWrites == .empty)
        #expect(d.semanticReads.mask == (UInt64(1) << 0))
    }

    @Test func releaseStoreAliasForm() {
        // 0xb860001f = staddl w0, [x0] — Rt=ZR, A=0, R=1.
        let d = decode(0xB860_001F)
        #expect(d.mnemonic == .staddl)
        #expect(d.memoryOrdering == [.release])
        #expect(d.operands.count == 2)
    }

    @Test func swpDoesNotCollapseEvenWithZeroDestination() {
        // 0x3820801f = swpb w0, wzr, [x0] — SWP has no ST alias.
        let d = decode(0x3820_801F)
        #expect(d.mnemonic == .swpb)
        #expect(d.operands.count == 3)
    }

    @Test func acquireBitSuppressesTheStoreAlias() {
        // 0x38a0001f — Rt=ZR but A=1 keeps the LD form (ldaddab).
        let d = decode(0x38A0_001F)
        #expect(d.mnemonic == .ldaddab)
        #expect(d.operands.count == 3)
    }

    @Test func opField1001DecodesRcwClear() {
        // op field 1001 is FEAT_THE RCWCLR (read-check-write), not reserved —
        // llvm-mc decodes 0x38209000 as `rcwclr x0, x0, [x0]`.
        let d = decode(0x3820_9000)
        #expect(d.mnemonic == .rcwclr)
        #expect(d.category == .loadsAndStores)
    }

    @Test func distinctRegistersProveTheAtomicReadWriteRoles() {
        // 0xb8210062 = ldadd w1, w2, [x3] — distinct Rs / Rt / Rn so the
        // operand source Rs, the loaded-value destination Rt and the base
        // are separable bits. An RMW reads Rs + Rn and writes Rt.
        let d = decode(0xB821_0062)
        #expect(d.mnemonic == .ldadd)
        #expect(Array(d.operands) == [
            .register(.w(1)), .register(.w(2)),
            .memory(MemoryOperand(base: .register(.x(3)))),
        ])
        #expect(d.semanticReads.mask == (UInt64(1) << 1) | (UInt64(1) << 3))
        #expect(d.semanticWrites.mask == UInt64(1) << 2)
    }
}

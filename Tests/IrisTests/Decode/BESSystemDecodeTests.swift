// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates SystemDecode sub-dispatch: bits 23:22 MUST
/// be 00 (constant prefix), bits 20:19 = op0_lsbs routes between
/// control / SYS / SYSL / MSR-reg / MRS sub-tiers, bits 15:12 routes
/// within the control sub-tier, fixed-field checks reject reserved
/// encodings. This suite focuses on the SUB-DISPATCH ITSELF (boundary
/// cases that don't fit elsewhere) — per-family decoders have their
/// own suites.
@Suite("BES / SystemDecode sub-dispatch")
struct BESSystemDecodeTests {
    @Test func bits23OneIsUndefined() {
        // bit 23 = 1 violates constant prefix → UNDEFINED
        // 0xD580_0000 → bit 23 = 1
        let d = decode(0xD580_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func bits22OneIsD128MovePair() {
        // bit 22 = 1 → FEAT_D128 form. 0xD540_0000 = MSRR (L=0, op0=0).
        let d = decode(0xD540_0000, at: 0)
        #expect(d.mnemonic == .msrr)
    }

    @Test func op0ZeroWithLOneIsMrs() {
        // bits 20:19 = 00, L = 1 → MRS with op0 = 0 (a `S0_…` register).
        // 0xD520_0000.
        let d = decode(0xD520_0000, at: 0)
        #expect(d.mnemonic == .mrs)
    }

    @Test func hintRoutedViaBits15to12Equal0010() {
        // bits 15:12 = 0010 → HINT route. Use HINT 0 = NOP.
        let d = decode(0xD503_201F, at: 0)
        #expect(d.mnemonic == .nop)
    }

    @Test func hintWithNonZrRtIsMsr() {
        // bits 15:12 = 0010 but Rt != 11111 → not a HINT; an op0 == 0 MSR
        // (the oracle renders `msr S0_3_C2_C0_0, x16`).
        let d = decode(0xD503_2010, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierRoutedViaBits15to12Equal0011() {
        let d = decode(0xD503_3F9F, at: 0)
        #expect(d.mnemonic == .dsb)
    }

    @Test func barrierWithNonZrRtIsMsr() {
        // bits 15:12 = 0011 but Rt != 11111 → not a barrier; an op0 == 0 MSR.
        let d = decode(0xD503_3F90, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func msrImmRoutedViaBits15to12Equal0100() {
        let d = decode(0xD500_401F, at: 0)
        #expect(d.mnemonic == .cfinv)
    }

    @Test func msrImmWithNonZrRtIsMsr() {
        // bits 15:12 = 0100 but Rt != 11111 → not MSR-imm; an op0 == 0 MSR
        // (the oracle renders `msr S0_0_C4_C0_0, x16`).
        let d = decode(0xD500_4010, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func wfxtRoutedViaBits15to12Equal0001() {
        let d = decode(0xD503_1000, at: 0)
        #expect(d.mnemonic == .wfet)
    }

    @Test func op0ZeroNonControlCRnIsMsr() {
        // bits 20:19 = 00, CRn = 0 (no control pattern) → op0 == 0 MSR
        // (the oracle renders `msr S0_3_C0_C0_0, x0`).
        let d = decode(0xD503_0000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func op0ZeroCRn5IsMsr() {
        // bits 20:19 = 00, CRn = 5 (not a control CRn) → op0 == 0 MSR.
        let d = decode(0xD503_5000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func sysRoutedViaOp0Lsbs01() {
        // bits 20:19 = 01 → SYS family.
        let d = decode(0xD508_711F, at: 0)
        #expect(d.mnemonic == .sys)
    }

    @Test func syslRoutedViaOp0Lsbs01PlusL1() {
        // bits 20:19 = 01, L = 1 → SYSL
        let d = decode(0xD52B_7C20, at: 0)
        #expect(d.mnemonic == .sysl)
    }

    @Test func msrRegRoutedViaOp0Lsbs10() {
        // bits 20:19 = 10 (op0=2 form, L=0) → MSR
        let d = decode(0xD513_0000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func msrRegRoutedViaOp0Lsbs11() {
        // bits 20:19 = 11 (op0=3, L=0) → MSR
        let d = decode(0xD51B_D040, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func mrsRoutedViaOp0Lsbs11PlusL1() {
        // bits 20:19 = 11, L = 1 → MRS
        let d = decode(0xD53B_D040, at: 0)
        #expect(d.mnemonic == .mrs)
    }
}

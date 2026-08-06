// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the System sub-dispatch itself.
@Suite("BES / SystemDecode sub-dispatch")
struct BESSystemDecodeTests {
    @Test func bits23OneIsTIndexChange() {
        let d = decode(0xD580_0000, at: 0)
        #expect(d.mnemonic == .tchangef)
    }

    @Test func bits23And22BothOneIsUndefined() {
        let d = decode(0xD5C0_0000, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func bits22OneIsD128MovePair() {
        let d = decode(0xD540_0000, at: 0)
        #expect(d.mnemonic == .msrr)
    }

    @Test func op0ZeroWithLOneIsMrs() {
        let d = decode(0xD520_0000, at: 0)
        #expect(d.mnemonic == .mrs)
    }

    @Test func hintRoutedViaBits15to12Equal0010() {
        let d = decode(0xD503_201F, at: 0)
        #expect(d.mnemonic == .nop)
    }

    @Test func hintWithNonZrRtIsMsr() {
        let d = decode(0xD503_2010, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func barrierRoutedViaBits15to12Equal0011() {
        let d = decode(0xD503_3F9F, at: 0)
        #expect(d.mnemonic == .dsb)
    }

    @Test func barrierWithNonZrRtIsMsr() {
        let d = decode(0xD503_3F90, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func msrImmRoutedViaBits15to12Equal0100() {
        let d = decode(0xD500_401F, at: 0)
        #expect(d.mnemonic == .cfinv)
    }

    @Test func msrImmWithNonZrRtIsMsr() {
        let d = decode(0xD500_4010, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func wfxtRoutedViaBits15to12Equal0001() {
        let d = decode(0xD503_1000, at: 0)
        #expect(d.mnemonic == .wfet)
    }

    @Test func op0ZeroNonControlCRnIsMsr() {
        let d = decode(0xD503_0000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func op0ZeroCRn5IsMsr() {
        let d = decode(0xD503_5000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func sysRoutedViaOp0Lsbs01() {
        let d = decode(0xD508_711F, at: 0)
        #expect(d.mnemonic == .sys)
    }

    @Test func syslRoutedViaOp0Lsbs01PlusL1() {
        let d = decode(0xD52B_7C20, at: 0)
        #expect(d.mnemonic == .sysl)
    }

    @Test func msrRegRoutedViaOp0Lsbs10() {
        let d = decode(0xD513_0000, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func msrRegRoutedViaOp0Lsbs11() {
        let d = decode(0xD51B_D040, at: 0)
        #expect(d.mnemonic == .msr)
    }

    @Test func mrsRoutedViaOp0Lsbs11PlusL1() {
        let d = decode(0xD53B_D040, at: 0)
        #expect(d.mnemonic == .mrs)
    }
}

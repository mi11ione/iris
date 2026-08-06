// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisValidation
import Testing

/// Golden encodings, operand shapes, semantic reads/writes and branch classes
/// for the Apple TIndex instructions TCHANGEB / TCHANGEF, TENTER and TEXIT,
/// plus the reserved-field rejections around each.
@Suite("BES / Apple TIndex — TCHANGE, TENTER, TEXIT")
struct BESTIndexTests {
    private static let registerForms: [(UInt32, Mnemonic, String)] = [
        (0xD580_0002, .tchangef, "tchangef x2, x0"),
        (0xD582_0002, .tchangefNb, "tchangef x2, x0, nb"),
        (0xD584_0002, .tchangeb, "tchangeb x2, x0"),
        (0xD586_0002, .tchangebNb, "tchangeb x2, x0, nb"),
        (0xD580_03E2, .tchangef, "tchangef x2, xzr"),
        (0xD586_00BF, .tchangebNb, "tchangeb xzr, x5, nb"),
    ]

    private static let immediateForms: [(UInt32, Mnemonic, String)] = [
        (0xD590_0017, .tchangef, "tchangef x23, #0"),
        (0xD592_0C77, .tchangefNb, "tchangef x23, #99, nb"),
        (0xD594_0C77, .tchangeb, "tchangeb x23, #99"),
        (0xD596_0017, .tchangebNb, "tchangeb x23, #0, nb"),
        (0xD590_0FFF, .tchangef, "tchangef xzr, #127"),
    ]

    @Test func tchangeRegisterFormsDecodeAndRender() {
        for (word, mnemonic, text) in Self.registerForms {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.category == .branchesExceptionSystem)
            #expect(d.branchClass == .none)
            #expect(d.operands.count == 2)
            #expect(BESSemanticChecker.verify(d) == nil)
        }
    }

    @Test func tchangeImmediateFormsDecodeAndRender() {
        for (word, mnemonic, text) in Self.immediateForms {
            let d = decode(word, at: 0)
            #expect(d.mnemonic == mnemonic, "0x\(String(word, radix: 16))")
            #expect(d.text == text)
            #expect(d.semanticReads.mask == 0)
            #expect(BESSemanticChecker.verify(d) == nil)
        }
    }

    @Test func tchangeCarriesExactRegisterSemantics() {
        let reg = decode(0xD580_00A2, at: 0)
        #expect(reg.semanticReads == RegisterSet.empty.inserting(.x(5)))
        #expect(reg.semanticWrites == RegisterSet.empty.inserting(.x(2)))
        let imm = decode(0xD590_0C77, at: 0)
        #expect(Array(imm.operands) == [.register(.x(23)), .unsignedImmediate(value: 99, width: 7)])
        #expect(imm.semanticWrites == RegisterSet.empty.inserting(.x(23)))
    }

    @Test func everyReservedTChangeSelectorIsUndefined() {
        for form: UInt32 in 0 ... 31 where form & 0b01001 != 0 {
            #expect(decode(0xD580_0000 | form << 16, at: 0).isUndefined, "form \(form)")
        }
        #expect(decode(0xD5A0_0000, at: 0).isUndefined)
        #expect(decode(0xD580_0400, at: 0).isUndefined)
        #expect(decode(0xD590_1000, at: 0).isUndefined)
    }

    @Test func tenterCoversTheWholeIndexAndItsNoBranchForm() {
        for index: UInt32 in 0 ... 127 {
            let plain = decode(0xD4E0_0000 | index << 5, at: 0)
            #expect(plain.mnemonic == .tenter, "index \(index)")
            #expect(plain.text == "tenter #\(index)")
            #expect(plain.branchClass == .exception)
            let noBranch = decode(0xD4E2_0000 | index << 5, at: 0)
            #expect(noBranch.mnemonic == .tenterNb, "index \(index)")
            #expect(noBranch.text == "tenter #\(index), nb")
            #expect(BESSemanticChecker.verify(noBranch) == nil)
        }
    }

    @Test func tenterReservedImmediateBitsAreUndefined() {
        for reserved: UInt32 in [1 << 12, 1 << 13, 1 << 16, 1 << 18, 1 << 20] {
            #expect(decode(0xD4E0_0000 | reserved, at: 0).isUndefined, "bit \(reserved)")
        }
        #expect(decode(0xD4E0_0001, at: 0).isUndefined)
        #expect(decode(0xD4E0_0004, at: 0).isUndefined)
    }

    @Test func texitAndItsNoBranchForm() {
        let plain = decode(0xD6FF_03E0, at: 0)
        #expect(plain.mnemonic == .texit)
        #expect(plain.text == "texit")
        #expect(plain.branchClass == .return)
        #expect(plain.operands.isEmpty)
        #expect(BESSemanticChecker.verify(plain) == nil)
        let noBranch = decode(0xD6FF_07E0, at: 0)
        #expect(noBranch.mnemonic == .texitNb)
        #expect(noBranch.text == "texit nb")
        #expect(noBranch.branchClass == .return)
        #expect(BESSemanticChecker.verify(noBranch) == nil)
    }

    @Test func texitRejectsEveryOtherFieldCombination() {
        #expect(decode(0xD6FF_00E0, at: 0).isUndefined)
        #expect(decode(0xD6FF_03E1, at: 0).isUndefined)
        #expect(decode(0xD6FF_0BE0, at: 0).isUndefined)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the FEAT_CMPBR compare-and-branch family: CB<cc> register
/// (W and X), CBB<cc> byte, CBH<cc> halfword, and CB<cc> immediate —
/// every cc arm of all four mnemonic maps, the reserved cc values
/// (100/101), the reserved bits15:14 = 01 class, the sf=1 rejections of
/// the byte/halfword forms, the fixed bit-14 of the immediate form, and
/// the signed imm9 (scaled-by-4) label with `branchTarget` resolution.
@Suite("BES / FEAT_CMPBR compare-and-branch")
struct BESCompareBranchRegTests {
    /// Register-form word: `sf 1110100 cc Rm 00 imm9 Rt`.
    private func registerWord(
        sf: UInt32, cc: UInt32, rm: UInt32, bits15_14: UInt32, imm9: UInt32, rt: UInt32,
    ) -> UInt32 {
        sf << 31 | 0x74 << 24 | cc << 21 | rm << 16 | bits15_14 << 14 | imm9 << 5 | rt
    }

    /// Immediate-form word: `sf 1110101 cc imm6 0 imm9 Rt`.
    private func immediateWord(
        sf: UInt32, cc: UInt32, imm6: UInt32, bit14: UInt32, imm9: UInt32, rt: UInt32,
    ) -> UInt32 {
        sf << 31 | 0x75 << 24 | cc << 21 | imm6 << 15 | bit14 << 14 | imm9 << 5 | rt
    }

    @Test func registerFormDecodesEveryConditionAtBothWidths() {
        let rows: [(cc: UInt32, mnemonic: Mnemonic, name: String)] = [
            (0b000, .cbgt, "cbgt"), (0b001, .cbge, "cbge"),
            (0b010, .cbhi, "cbhi"), (0b011, .cbhs, "cbhs"),
            (0b110, .cbeq, "cbeq"), (0b111, .cbne, "cbne"),
        ]
        for row in rows {
            let w = decode(registerWord(sf: 0, cc: row.cc, rm: 2, bits15_14: 0b00, imm9: 4, rt: 1))
            #expect(w.mnemonic == row.mnemonic)
            #expect(w.category == .branchesExceptionSystem)
            #expect(w.branchClass == .conditional)
            #expect(Array(w.operands) == [
                .register(.w(1)), .register(.w(2)), .label(byteOffset: 16),
            ])
            #expect(w.semanticReads.contains(.w(1)) && w.semanticReads.contains(.w(2)))
            #expect(w.text == "\(row.name) w1, w2, #16")

            let x = decode(registerWord(sf: 1, cc: row.cc, rm: 2, bits15_14: 0b00, imm9: 4, rt: 1))
            #expect(x.mnemonic == row.mnemonic)
            #expect(Array(x.operands) == [
                .register(.x(1)), .register(.x(2)), .label(byteOffset: 16),
            ])
            #expect(x.text == "\(row.name) x1, x2, #16")
        }
    }

    @Test func byteFormDecodesEveryConditionAsWRegisters() {
        let rows: [(cc: UInt32, mnemonic: Mnemonic, name: String)] = [
            (0b000, .cbbgt, "cbbgt"), (0b001, .cbbge, "cbbge"),
            (0b010, .cbbhi, "cbbhi"), (0b011, .cbbhs, "cbbhs"),
            (0b110, .cbbeq, "cbbeq"), (0b111, .cbbne, "cbbne"),
        ]
        for row in rows {
            let d = decode(registerWord(sf: 0, cc: row.cc, rm: 3, bits15_14: 0b10, imm9: 8, rt: 0))
            #expect(d.mnemonic == row.mnemonic)
            #expect(d.branchClass == .conditional)
            #expect(Array(d.operands) == [
                .register(.w(0)), .register(.w(3)), .label(byteOffset: 32),
            ])
            #expect(d.text == "\(row.name) w0, w3, #32")
        }
    }

    @Test func halfwordFormDecodesEveryConditionAsWRegisters() {
        let rows: [(cc: UInt32, mnemonic: Mnemonic, name: String)] = [
            (0b000, .cbhgt, "cbhgt"), (0b001, .cbhge, "cbhge"),
            (0b010, .cbhhi, "cbhhi"), (0b011, .cbhhs, "cbhhs"),
            (0b110, .cbheq, "cbheq"), (0b111, .cbhne, "cbhne"),
        ]
        for row in rows {
            let d = decode(registerWord(sf: 0, cc: row.cc, rm: 4, bits15_14: 0b11, imm9: 8, rt: 5))
            #expect(d.mnemonic == row.mnemonic)
            #expect(Array(d.operands) == [
                .register(.w(5)), .register(.w(4)), .label(byteOffset: 32),
            ])
            #expect(d.text == "\(row.name) w5, w4, #32")
        }
    }

    @Test func immediateFormDecodesEveryConditionAtBothWidths() {
        let rows: [(cc: UInt32, mnemonic: Mnemonic, name: String)] = [
            (0b000, .cbgt, "cbgt"), (0b001, .cblt, "cblt"),
            (0b010, .cbhi, "cbhi"), (0b011, .cblo, "cblo"),
            (0b110, .cbeq, "cbeq"), (0b111, .cbne, "cbne"),
        ]
        for row in rows {
            let w = decode(immediateWord(sf: 0, cc: row.cc, imm6: 5, bit14: 0, imm9: 4, rt: 1))
            #expect(w.mnemonic == row.mnemonic)
            #expect(w.branchClass == .conditional)
            #expect(Array(w.operands) == [
                .register(.w(1)),
                .unsignedImmediate(value: 5, width: 6),
                .label(byteOffset: 16),
            ])
            #expect(w.semanticReads.contains(.w(1)))
            #expect(w.text == "\(row.name) w1, #5, #16")

            let x = decode(immediateWord(sf: 1, cc: row.cc, imm6: 63, bit14: 0, imm9: 4, rt: 2))
            #expect(x.mnemonic == row.mnemonic)
            #expect(x.text == "\(row.name) x2, #63, #16")
        }
    }

    @Test func negativeOffsetSignExtendsAndScalesBy4() {
        // imm9 = 0x1FF = -1 → byte offset -4.
        let d = decode(registerWord(sf: 1, cc: 0b000, rm: 2, bits15_14: 0b00, imm9: 0x1FF, rt: 1),
                       at: 0x1000)
        #expect(Array(d.operands) == [
            .register(.x(1)), .register(.x(2)), .label(byteOffset: -4),
        ])
        #expect(d.branchTarget == 0x0FFC)
        #expect(d.text == "cbgt x1, x2, #-4")
    }

    @Test func branchTargetResolvesForwardForAllFourForms() {
        let reg = decode(registerWord(sf: 0, cc: 0b110, rm: 2, bits15_14: 0b00, imm9: 4, rt: 1), at: 0x4000)
        let byte = decode(registerWord(sf: 0, cc: 0b110, rm: 2, bits15_14: 0b10, imm9: 4, rt: 1), at: 0x4000)
        let half = decode(registerWord(sf: 0, cc: 0b110, rm: 2, bits15_14: 0b11, imm9: 4, rt: 1), at: 0x4000)
        let imm = decode(immediateWord(sf: 0, cc: 0b110, imm6: 1, bit14: 0, imm9: 4, rt: 1), at: 0x4000)
        for d in [reg, byte, half, imm] {
            #expect(d.branchTarget == 0x4010)
        }
    }

    @Test func reservedConditionCodesAreUndefinedInEveryForm() {
        for cc: UInt32 in [0b100, 0b101] {
            #expect(decode(registerWord(sf: 0, cc: cc, rm: 2, bits15_14: 0b00, imm9: 4, rt: 1)).isUndefined)
            #expect(decode(registerWord(sf: 0, cc: cc, rm: 2, bits15_14: 0b10, imm9: 4, rt: 1)).isUndefined)
            #expect(decode(registerWord(sf: 0, cc: cc, rm: 2, bits15_14: 0b11, imm9: 4, rt: 1)).isUndefined)
            #expect(decode(immediateWord(sf: 0, cc: cc, imm6: 5, bit14: 0, imm9: 4, rt: 1)).isUndefined)
        }
    }

    @Test func reservedBits15_14IsUndefined() {
        let d = decode(registerWord(sf: 0, cc: 0b000, rm: 2, bits15_14: 0b01, imm9: 4, rt: 1))
        #expect(d.isUndefined)
        #expect(d.encoding == registerWord(sf: 0, cc: 0b000, rm: 2, bits15_14: 0b01, imm9: 4, rt: 1))
    }

    @Test func byteAndHalfwordFormsRequireSfZero() {
        #expect(decode(registerWord(sf: 1, cc: 0b000, rm: 2, bits15_14: 0b10, imm9: 4, rt: 1)).isUndefined)
        #expect(decode(registerWord(sf: 1, cc: 0b000, rm: 2, bits15_14: 0b11, imm9: 4, rt: 1)).isUndefined)
    }

    @Test func immediateFormRequiresBit14Zero() {
        let d = decode(immediateWord(sf: 0, cc: 0b000, imm6: 5, bit14: 1, imm9: 4, rt: 1))
        #expect(d.isUndefined)
    }
}

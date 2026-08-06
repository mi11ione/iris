// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates AMX decode.
@Suite("AMX / AMXDecoder")
struct AMXDecoderTests {
    @Test func nonAMXEncodingReturnsUndefined() {
        let d = decode(0x0100_0000, at: 0)
        #expect(d.mnemonic == .undefined)
        #expect(d.encoding == 0x0100_0000)
    }

    @Test func adjacentAppleProprietaryEncodingsAreNotAMX() {
        let genterBase: UInt32 = 0x0020_1400
        let d = decode(genterBase, at: 0)
        #expect(d.mnemonic == .undefined)
    }

    @Test func documentedOpcodeMnemonics() {
        let cases: [(UInt32, Mnemonic)] = [
            (0, .amxLdx), (1, .amxLdy), (2, .amxStx), (3, .amxSty),
            (4, .amxLdz), (5, .amxStz), (6, .amxLdzi), (7, .amxStzi),
            (8, .amxExtrx), (9, .amxExtry),
            (10, .amxFma64), (11, .amxFms64), (12, .amxFma32), (13, .amxFms32),
            (14, .amxMac16), (15, .amxFma16), (16, .amxFms16),
            (18, .amxVecint), (19, .amxVecfp),
            (20, .amxMatint), (21, .amxMatfp), (22, .amxGenlut),
        ]
        for (opcode, expected) in cases {
            let encoding = 0x0020_1000 | (opcode << 5)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == expected,
                    "opcode \(opcode) expected \(expected.rawValue) got \(d.mnemonic.rawValue)")
            #expect(d.category == .amx)
            #expect(Array(d.operands) == [.amxField(AMXField(rawBits: encoding))])
        }
    }

    @Test func documentedOpcodeProducesAmxFieldOperandWithFullEncoding() {
        let encoding: UInt32 = 0x0020_1000 | (10 << 5) | 5
        let d = decode(encoding, at: 0xCAFE)
        #expect(Array(d.operands) == [.amxField(AMXField(rawBits: encoding))])
        #expect(d.encoding == encoding)
        #expect(d.address == 0xCAFE)
    }

    @Test func opcodeReadsXRegisterFromOperandField() {
        let encoding: UInt32 = 0x0020_1000 | (4 << 5) | 5
        let d = decode(encoding, at: 0)
        #expect(d.semanticReads.contains(.x(5)))
    }

    @Test func opcodeWithXZRDoesNotInsertReadIntoSet() {
        let encoding: UInt32 = 0x0020_1000 | (4 << 5) | 31
        let d = decode(encoding, at: 0)
        #expect(d.semanticReads == .empty)
    }

    @Test func opcode17ImmediateZeroIsSet() {
        let encoding: UInt32 = 0x0020_1000 | (17 << 5) | 0
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .amxSet)
        #expect(d.category == .amx)
        #expect(d.semanticReads == .empty)
        #expect(Array(d.operands) == [.amxField(AMXField(rawBits: encoding))])
    }

    @Test func opcode17ImmediateOneIsClr() {
        let encoding: UInt32 = 0x0020_1000 | (17 << 5) | 1
        let d = decode(encoding, at: 0)
        #expect(d.mnemonic == .amxClr)
        #expect(d.semanticReads == .empty)
        #expect(Array(d.operands) == [.amxField(AMXField(rawBits: encoding))])
    }

    @Test func opcode17ImmediateTwoOrAboveIsAmxUnknownOp() {
        for imm: UInt32 in [2, 3, 7, 15, 31] {
            let encoding: UInt32 = 0x0020_1000 | (17 << 5) | imm
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .amxUnknownOp, "imm=\(imm)")
            #expect(d.category == .amx)
            #expect(Array(d.operands) == [.amxUnknown(rawFields: encoding)],
                    "operand mismatch for imm=\(imm)")
        }
    }

    @Test func opcodes23To31SurfaceAsAmxUnknownOp() {
        for opcode: UInt32 in 23 ... 31 {
            let encoding: UInt32 = 0x0020_1000 | (opcode << 5)
            let d = decode(encoding, at: 0)
            #expect(d.mnemonic == .amxUnknownOp, "opcode \(opcode)")
            #expect(d.category == .amx)
            #expect(Array(d.operands) == [.amxUnknown(rawFields: encoding)],
                    "operand mismatch for opcode \(opcode)")
        }
    }

    @Test func unknownOpcodeProducesNoSemanticReadOrWrite() {
        let d = decode(0x0020_1000 | (23 << 5) | 5, at: 0)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == .empty)
    }

    @Test func registeredAtTheReservedOp0ZeroSlot() {
        #expect(decode(0x0020_1000).category == .amx)
    }
}

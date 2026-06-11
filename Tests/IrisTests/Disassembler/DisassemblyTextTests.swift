// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates `normalizeDisassembly(_:)` — the public Sources/Iris/
/// helper that strips ARM `;` comments, lowercases, and collapses
/// whitespace so two disassembly strings compare equal regardless of
/// the source tool's formatting whim.
@Suite("Disassembler / normalizeDisassembly")
struct DisassemblyTextTests {
    @Test func emptyInputProducesEmptyOutput() {
        #expect(normalizeDisassembly("") == "")
    }

    @Test func leadingAndTrailingWhitespaceStripped() {
        #expect(normalizeDisassembly("   add x0, x1, #1   ") == "add x0, x1, #1")
    }

    @Test func internalTabsCollapseToSingleSpaces() {
        #expect(normalizeDisassembly("\tadd\tx0,\tx1,\t#1") == "add x0, x1, #1")
    }

    @Test func multipleSpacesCollapseToSingleSpaces() {
        #expect(normalizeDisassembly("add    x0,     x1,   #1") == "add x0, x1, #1")
    }

    @Test func uppercaseInputLowercased() {
        #expect(normalizeDisassembly("ADD X0, X1, #1") == "add x0, x1, #1")
    }

    @Test func semicolonCommentStripped() {
        #expect(normalizeDisassembly("add x0, x1, #1 ; =0x1") == "add x0, x1, #1")
    }

    @Test func semicolonAtStartProducesEmpty() {
        #expect(normalizeDisassembly("; comment only") == "")
    }

    @Test func mixedTabsSpacesAndNewlinesCollapse() {
        #expect(normalizeDisassembly("add\t x0,\n x1,  #1") == "add x0, x1, #1")
    }

    @Test func commentInsideOperandsStripsTailBeforeComma() {
        #expect(normalizeDisassembly("add x0, x1, #4 ; some comment, with commas") == "add x0, x1, #4")
    }
}

/// Pins the text router's truncated-tail `.byte` arm: real residual tails
/// from the bytes-in path render exactly `tailByteCount` two-digit
/// lowercase hex bytes; hand-built counts clamp to the four bytes the
/// packed encoding carries; a zero-count tail renders the bare directive.
@Suite("DisassemblyText / truncated-tail rendering")
struct TruncatedTailTextTests {
    @Test func oneResidualByteRendersDotByte() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0xAB], at: 0)
        #expect(stream.last?.text == ".byte 0xab")
    }

    @Test func twoResidualBytesPadSingleDigitToTwoHexDigits() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0xAB, 0x0C], at: 0)
        #expect(stream.last?.text == ".byte 0xab, 0x0c")
    }

    @Test func threeResidualBytesJoinWithCommaSpace() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0x11, 0x22, 0x33], at: 0)
        #expect(stream.last?.text == ".byte 0x11, 0x22, 0x33")
    }

    @Test func handBuiltTailCountClampsToTheFourCarriedBytes() {
        let record = InstructionRecord(
            address: 0,
            semanticReads: .empty,
            semanticWrites: .empty,
            encoding: 0x4433_2211,
            operandStart: 0,
            mnemonic: .truncatedTail,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .truncatedTail,
            operandCount: 7,
        )
        let stream = InstructionStream(
            baseAddress: 0,
            byteCount: 4,
            features: [],
            records: [record],
            operands: [],
            diagnostics: [],
        )
        #expect(stream[0].text == ".byte 0x11, 0x22, 0x33, 0x44")
    }

    @Test func handBuiltZeroCountTailRendersBareByteDirective() {
        let record = InstructionRecord(
            address: 0,
            semanticReads: .empty,
            semanticWrites: .empty,
            encoding: 0,
            operandStart: 0,
            mnemonic: .truncatedTail,
            branchClass: .none,
            memoryAccess: .none,
            memoryOrdering: [],
            flagEffect: .none,
            category: .truncatedTail,
            operandCount: 0,
        )
        let stream = InstructionStream(
            baseAddress: 0,
            byteCount: 0,
            features: [],
            records: [record],
            operands: [],
            diagnostics: [],
        )
        #expect(stream[0].text == ".byte")
    }
}

/// Pins `Instruction`'s `CustomStringConvertible` conformance:
/// `description` is exactly the canonical `text`.
@Suite("Instruction / description mirrors text")
struct InstructionDescriptionTests {
    @Test func descriptionIsCanonicalText() {
        let nop = decode(0xD503_201F)
        #expect(nop.description == "nop")
        #expect(nop.description == nop.text)
    }
}

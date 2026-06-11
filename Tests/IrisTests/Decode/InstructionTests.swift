// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates the Instruction materializing initializer — defaults,
/// full-argument field preservation, and the explicit truncated-tail
/// operand-window rule.
@Suite("Instruction / materializing init defaults and field preservation")
struct InstructionMaterializingInitTests {
    @Test func initWithDefaultsPopulatesMandatoryFields() {
        let instruction = Instruction(
            address: 0x1000,
            encoding: 0xCAFE_BABE,
            mnemonic: .undefined,
            category: .undefined,
        )
        #expect(instruction.address == 0x1000)
        #expect(instruction.encoding == 0xCAFE_BABE)
        #expect(instruction.mnemonic == .undefined)
        #expect(instruction.semanticReads == .empty)
        #expect(instruction.semanticWrites == .empty)
        #expect(instruction.branchClass == .none)
        #expect(instruction.memoryAccess == .none)
        #expect(instruction.memoryOrdering == [])
        #expect(instruction.flagEffect == .none)
        #expect(instruction.category == .undefined)
        #expect(instruction.operands.isEmpty)
        #expect(instruction.record.operandStart == 0)
    }

    @Test func initWithFullArgsPreservesAllFields() {
        let instruction = Instruction(
            address: 0x4000,
            encoding: 0xAA55_AA55,
            mnemonic: .ldr,
            semanticReads: RegisterSet(mask: 0x1),
            semanticWrites: RegisterSet(mask: 0x2),
            branchClass: .call,
            memoryAccess: .atomic,
            memoryOrdering: [.acquire, .release],
            flagEffect: .nzcv,
            category: .loadsAndStores,
            operands: [.immediate(value: 9, width: 8)],
        )
        #expect(instruction.semanticReads.mask == 0x1)
        #expect(instruction.semanticWrites.mask == 0x2)
        #expect(instruction.branchClass == .call)
        #expect(instruction.memoryAccess == .atomic)
        #expect(instruction.memoryOrdering.contains(.acquire))
        #expect(instruction.memoryOrdering.contains(.release))
        #expect(instruction.flagEffect == .nzcv)
        #expect(instruction.category == .loadsAndStores)
        #expect(instruction.operands.count == 1)
        #expect(Array(instruction.operands) == [.immediate(value: 9, width: 8)])
    }

    @Test func truncatedTailCategoryFormsEmptyOperandWindow() {
        // The truncated-tail contract: tail records carry no operands,
        // so the operand view forms empty even for hand-supplied lists; the
        // record's operandCount still reflects the argument (it carries
        // the residual-byte meaning on tails).
        let tail = Instruction(
            address: 0,
            encoding: 0xAB,
            mnemonic: .truncatedTail,
            category: .truncatedTail,
            operands: [.immediate(value: 1, width: 8)],
        )
        #expect(tail.operands.isEmpty)
        #expect(tail.operands.count == 0)
        #expect(tail.record.tailByteCount == 1)
    }
}

/// Validates that the decoder's sentinel shapes (UNDEFINED,
/// data-marker, truncated-tail, UDF) are reproducible through the public
/// surface with their documented field contents.
@Suite("Instruction / sentinel production through public decode paths")
struct InstructionSentinelProductionTests {
    @Test func undefinedPreservesEncodingAndEmptiesSemantics() {
        let d = decode(0x0200_0000, at: 0x100)
        #expect(d.isUndefined)
        #expect(d.address == 0x100)
        #expect(d.encoding == 0x0200_0000)
        #expect(d.mnemonic == .undefined)
        #expect(d.operands.isEmpty)
        #expect(d.semanticReads == .empty)
        #expect(d.semanticWrites == .empty)
        #expect(d.branchClass == .none)
        #expect(d.memoryAccess == .none)
        #expect(d.flagEffect == .none)
    }

    @Test func dataMarkerPreservesEncoding() {
        let stream = InstructionStream(
            bytes: [0x78, 0x56, 0x34, 0x12],
            at: 0x200,
            dataInCode: [DataInCodeSpan(offset: 0, length: 4, kind: .data)],
        )
        let marker = stream.records[0]
        #expect(marker.address == 0x200)
        #expect(marker.encoding == 0x1234_5678)
        #expect(marker.mnemonic == .dataMarker)
        #expect(marker.category == .dataInCodeMarker)
        #expect(marker.operandCount == 0)
    }

    @Test func truncatedTailPacksResidualBytesLittleEndianLow() {
        // One, two, and three residual bytes pack at the low bits with
        // high bits zero; operandCount carries the residual length.
        let one = InstructionStream(bytes: [0xAB], at: 0x300).records[0]
        #expect(one.encoding == 0x0000_00AB)
        #expect(one.mnemonic == .truncatedTail)
        #expect(one.category == .truncatedTail)
        #expect(one.tailByteCount == 1)
        let two = InstructionStream(bytes: [0xAB, 0xCD], at: 0x400).records[0]
        #expect(two.encoding == 0x0000_CDAB)
        #expect(two.tailByteCount == 2)
        let three = InstructionStream(bytes: [0xAB, 0xCD, 0xEF], at: 0x500).records[0]
        #expect(three.encoding == 0x00EF_CDAB)
        #expect(three.tailByteCount == 3)
    }

    @Test func truncatedTailHighBitsAreZeroForEveryResidualLength() {
        for residualLength in 1 ... 3 {
            let bytes = Array(repeating: UInt8(0xFF), count: residualLength)
            let tail = InstructionStream(bytes: bytes, at: 0).records[0]
            let highMask: UInt32 = (residualLength == 3) ? 0xFF00_0000 : (residualLength == 2 ? 0xFFFF_0000 : 0xFFFF_FF00)
            #expect((tail.encoding & highMask) == 0,
                    "high bits non-zero for residualLength=\(residualLength)")
        }
    }
}

/// Validates Instruction's semantic equality and hashing: side-buffer
/// indices are excluded, operand content participates, and equal values
/// hash equal — including across differently-laid-out streams.
@Suite("Instruction / semantic equality and hashing")
struct InstructionEqualityTests {
    @Test func equalInstructionsFromDifferentStreamsCompareEqual() {
        // The same ADD word sits at different operand-buffer offsets in
        // the two streams (stream B has a NOP-free prefix instruction
        // with operands), so the records' operandStart differ while the
        // instructions are semantically identical.
        let wordBytes: [UInt8] = [0x00, 0x04, 0x00, 0x91] // add x0, x0, #1
        let prefix: [UInt8] = [0x41, 0x08, 0x00, 0xB1] //    adds x1, x2, #2
        let a = InstructionStream(bytes: wordBytes, at: 0x1000)
        let b = InstructionStream(bytes: prefix + wordBytes, at: 0xFFC)
        let lhs = a.instruction(at: 0x1000)?.record
        let rhs = b.instruction(at: 0x1000)?.record
        #expect(lhs != nil && rhs != nil)
        guard let lhs, let rhs else { return }
        #expect(lhs.operandStart != rhs.operandStart)
        let lhsInstruction = Instruction(
            address: lhs.address, encoding: lhs.encoding, mnemonic: lhs.mnemonic,
            semanticReads: lhs.semanticReads, semanticWrites: lhs.semanticWrites,
            branchClass: lhs.branchClass, memoryAccess: lhs.memoryAccess,
            memoryOrdering: lhs.memoryOrdering, flagEffect: lhs.flagEffect,
            category: lhs.category, operands: Array(a.operands(for: lhs)),
        )
        let rhsInstruction = Instruction(
            address: rhs.address, encoding: rhs.encoding, mnemonic: rhs.mnemonic,
            semanticReads: rhs.semanticReads, semanticWrites: rhs.semanticWrites,
            branchClass: rhs.branchClass, memoryAccess: rhs.memoryAccess,
            memoryOrdering: rhs.memoryOrdering, flagEffect: rhs.flagEffect,
            category: rhs.category, operands: Array(b.operands(for: rhs)),
        )
        #expect(lhsInstruction == rhsInstruction)
        #expect(lhsInstruction.hashValue == rhsInstruction.hashValue)
        // The raw records keep index-sensitive equality by design.
        #expect(lhs != rhs)
    }

    @Test func operandContentParticipatesInEquality() {
        let base = decode(0x9100_0400) // add x0, x0, #1
        let differentOperands = Instruction(
            address: base.address, encoding: base.encoding, mnemonic: base.mnemonic,
            semanticReads: base.semanticReads, semanticWrites: base.semanticWrites,
            flagEffect: base.flagEffect, category: base.category,
            operands: [.register(.x(1))],
        )
        #expect(base != differentOperands)
    }

    @Test func semanticFieldsParticipateInEquality() {
        let nop = decode(0xD503_201F)
        let sameDecode = decode(0xD503_201F)
        #expect(nop == sameDecode)
        #expect(nop.hashValue == sameDecode.hashValue)
        let elsewhere = decode(0xD503_201F, at: 4)
        #expect(nop != elsewhere)
    }
}

/// Validates the zero-based Operands view: indexing, iteration,
/// collection conformance, and content-wise equality across windows.
@Suite("Instruction / Operands view")
struct InstructionOperandsViewTests {
    @Test func operandsAreZeroBasedRegardlessOfBufferPosition() {
        // Second instruction in the stream: its operands live at a
        // non-zero side-buffer offset, but the view indexes from 0.
        let bytes: [UInt8] = [
            0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
            0x41, 0x08, 0x00, 0xB1, // adds x1, x2, #2
        ]
        let stream = InstructionStream(bytes: bytes, at: 0)
        let adds = stream.records[1]
        let window = stream.operands(for: adds)
        #expect(adds.operandStart == 3)
        #expect(window.count == 3)
        #expect(window.first == .register(.x(1)))
    }

    @Test func viewConformsToRandomAccessCollection() {
        let instruction = decode(0x9100_0400) // add x0, x0, #1
        let ops = instruction.operands
        #expect(ops.startIndex == 0)
        #expect(ops.endIndex == ops.count)
        #expect(ops.count == 3)
        #expect(ops[0] == .register(.x(0)))
        var collected: [Operand] = []
        for op in ops {
            collected.append(op)
        }
        #expect(collected.count == 3)
        #expect(Array(ops.reversed()).count == 3)
        #expect(ops.map(\.self) == collected)
    }

    @Test func equalWindowsFromDifferentBackingBuffersCompareEqual() {
        let standalone = decode(0x9100_0400) // own buffer
        let stream = InstructionStream(bytes: [0x00, 0x04, 0x00, 0x91], at: 0)
        let windowed = stream.operands(for: stream.records[0])
        #expect(standalone.operands.count == windowed.count)
        #expect(Array(standalone.operands) == Array(windowed))
        #expect(standalone.operands == standalone.operands)
    }

    @Test func windowsWithDifferentContentsCompareUnequal() {
        let add = decode(0x9100_0400).operands
        let nop = decode(0xD503_201F).operands
        #expect(add != nop)
        #expect(nop.isEmpty)
    }
}

/// Pins the custom-equality contract: semantically identical
/// instructions from streams with different side-buffer layouts compare
/// equal and hash equal, while their raw records — which carry the
/// side-buffer indices — compare unequal. A synthesized conformance
/// would fail every assertion in this suite.
@Suite("Instruction / cross-stream value semantics")
struct InstructionCrossStreamEqualityTests {
    private static func word(_ w: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: w),
            UInt8(truncatingIfNeeded: w >> 8),
            UInt8(truncatingIfNeeded: w >> 16),
            UInt8(truncatingIfNeeded: w >> 24),
        ]
    }

    @Test func sameInstructionAtDifferentOperandStartComparesAndHashesEqual() {
        // add x0, x0, #1 alone vs preceded by add x0, x1, x2 (three
        // operands), bases aligned so both decoded adds carry address
        // 0x1000 — identical semantics, different operandStart.
        let a = InstructionStream(bytes: Self.word(0x9100_0400), at: 0x1000)
        let b = InstructionStream(
            bytes: Self.word(0x8B02_0020) + Self.word(0x9100_0400),
            at: 0xFFC,
        )
        let lhs = a[address: 0x1000]
        let rhs = b[address: 0x1000]
        #expect(lhs != nil)
        #expect(rhs != nil)
        #expect(lhs == rhs)
        if let lhs, let rhs {
            #expect(lhs.record.operandStart != rhs.record.operandStart)
            #expect(lhs.record != rhs.record)
            #expect(lhs.operands == rhs.operands)
            #expect(Set([lhs, rhs]).count == 1)
        }
    }
}

/// Pins the computed `bufferOffset` projection over the wrap diagnostic's
/// payload (the data-in-code arm is pinned by the stream suites).
@Suite("Diagnostic / addressSpaceWrapped bufferOffset projection")
struct DiagnosticWrappedOffsetTests {
    @Test func wrappedKindProjectsItsOffset() {
        let d = Diagnostic(kind: .addressSpaceWrapped(offset: 4))
        #expect(d.bufferOffset == 4)
    }
}

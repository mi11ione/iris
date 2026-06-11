// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Materialize a standalone Instruction from a committed record plus its
/// operand window — exercises the public materializing init against
/// stream-decoded values.
private func instruction(for record: InstructionRecord, in stream: InstructionStream) -> Instruction {
    Instruction(
        address: record.address,
        encoding: record.encoding,
        mnemonic: record.mnemonic,
        semanticReads: record.semanticReads,
        semanticWrites: record.semanticWrites,
        branchClass: record.branchClass,
        memoryAccess: record.memoryAccess,
        memoryOrdering: record.memoryOrdering,
        flagEffect: record.flagEffect,
        category: record.category,
        operands: Array(stream.operands(for: record)),
    )
}

/// Little-endian byte expansion of one or more 4-byte instruction words.
private func bytes(of words: [UInt32]) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(words.count * 4)
    for word in words {
        out.append(UInt8(word & 0xFF))
        out.append(UInt8((word >> 8) & 0xFF))
        out.append(UInt8((word >> 16) & 0xFF))
        out.append(UInt8((word >> 24) & 0xFF))
    }
    return out
}

/// Validates the bytes-in decode entry points on well-known instruction
/// words: explicit little-endian word assembly, per-family mnemonic /
/// category / semantics attribution, and canonical text via the
/// per-family canonicalizers (expectations harvested from the copied
/// decoders' actual behavior).
@Suite struct WellKnownWordTests {
    @Test func nopDecodes() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5], at: 0x1000)
        #expect(stream.records.count == 1)
        let record = stream.records[0]
        #expect(record.encoding == 0xD503_201F)
        #expect(record.address == 0x1000)
        #expect(record.mnemonic == .nop)
        #expect(record.category == .branchesExceptionSystem)
        #expect(record.operandCount == 0)
        #expect(instruction(for: record, in: stream).text == "nop")
    }

    @Test func addImmediateDecodes() {
        let stream = InstructionStream(bytes: bytes(of: [0x9100_0400]), at: 0)
        let record = stream.records[0]
        #expect(record.mnemonic == .add)
        #expect(record.category == .dataProcessingImmediate)
        #expect(record.operandCount == 3)
        let operands = stream.operands(for: record)
        #expect(operands.count == 3)
        #expect(instruction(for: record, in: stream).text == "add x0, x0, #1")
    }

    @Test func branchAndLinkDecodes() {
        let stream = InstructionStream(bytes: bytes(of: [0x9400_0001]), at: 0x4000)
        let record = stream.records[0]
        #expect(record.mnemonic == .bl)
        #expect(record.category == .branchesExceptionSystem)
        #expect(record.branchClass == .call)
        #expect(instruction(for: record, in: stream).text == "bl #4")
    }

    @Test func loadRegisterDecodes() {
        let stream = InstructionStream(bytes: bytes(of: [0xF940_0021]), at: 0)
        let record = stream.records[0]
        #expect(record.mnemonic == .ldr)
        #expect(record.category == .loadsAndStores)
        #expect(record.memoryAccess == .load)
        #expect(instruction(for: record, in: stream).text == "ldr x1, [x1]")
    }

    @Test func fmovDoubleImmediateDecodes() {
        let stream = InstructionStream(bytes: bytes(of: [0x1E6E_1000]), at: 0)
        let record = stream.records[0]
        #expect(record.mnemonic == .fmov)
        #expect(record.category == .simdAndFP)
        #expect(record.operandCount == 2)
        #expect(instruction(for: record, in: stream).text == "fmov d0, #1.00000000")
    }

    @Test func arm64eGatesPACLoadStore() {
        let word: [UInt8] = bytes(of: [0xF820_0400])
        let plain = InstructionStream(bytes: word, at: 0)
        #expect(plain.records[0].mnemonic == .undefined)
        #expect(plain.records[0].category == .undefined)
        let pac = InstructionStream(bytes: word, at: 0, features: .arm64e)
        #expect(pac.records[0].mnemonic == .ldraa)
        #expect(pac.records[0].category == .loadsAndStores)
        #expect(pac.records[0].memoryAccess == .load)
    }

    @Test func pointerAndArrayEntriesAgree() {
        let raw = bytes(of: [0xD503_201F, 0x9100_0400, 0x9400_0001]) + [0xAB]
        let viaArray = InstructionStream(bytes: raw, at: 0x100)
        let viaPointer = raw.withUnsafeBytes { buffer in
            InstructionStream(bytes: buffer, at: 0x100)
        }
        #expect(viaArray.records == viaPointer.records)
        #expect(viaArray.operands == viaPointer.operands)
        #expect(viaArray.diagnostics == viaPointer.diagnostics)
        #expect(viaArray.byteCount == 13)
    }
}

/// Validates the stream's structural contracts: empty input, residual
/// truncated tails, address-indexed lookup, and the operand side buffer.
@Suite struct StreamShapeTests {
    @Test func emptyBufferYieldsEmptyStream() {
        let stream = InstructionStream(bytes: [], at: 0x10000)
        #expect(stream.records.isEmpty)
        #expect(stream.operands.isEmpty)
        #expect(stream.diagnostics.isEmpty)
        #expect(stream.baseAddress == 0x10000)
        #expect(stream.byteCount == 0)
        #expect(stream.instruction(at: 0x10000) == nil)
    }

    @Test func residualTailPacksLittleEndian() {
        let raw = bytes(of: [0xD503_201F]) + [0xAB, 0xCD]
        let stream = InstructionStream(bytes: raw, at: 0x2000)
        #expect(stream.records.count == 2)
        let tail = stream.records[1]
        #expect(tail.mnemonic == .truncatedTail)
        #expect(tail.category == .truncatedTail)
        #expect(tail.address == 0x2004)
        #expect(tail.encoding == 0xCDAB)
        // operandCount carries the residual byte count on tails.
        #expect(tail.operandCount == 2)
        #expect(tail.tailByteCount == 2)
    }

    @Test func singleResidualByteStream() {
        let stream = InstructionStream(bytes: [0x41], at: 0x8000)
        #expect(stream.records.count == 1)
        #expect(stream.records[0].mnemonic == .truncatedTail)
        #expect(stream.records[0].encoding == 0x41)
        #expect(stream.instruction(at: 0x8000)?.mnemonic == .truncatedTail)
    }

    @Test func addressLookupAPIs() {
        let raw = bytes(of: [0xD503_201F, 0x9100_0400])
        let stream = InstructionStream(bytes: raw, at: 0x1000)
        #expect(stream.instruction(at: 0x1000)?.mnemonic == .nop)
        #expect(stream.instruction(at: 0x1004)?.mnemonic == .add)
        #expect(stream.instruction(at: 0x1002) == nil)
        #expect(stream.instruction(at: 0x0FFC) == nil)
        #expect(stream.instruction(at: 0x1008) == nil)
        #expect(stream.instruction(containing: 0x1006)?.mnemonic == .add)
        #expect(stream[address: 0x1004]?.mnemonic == .add)
        #expect(stream[address: 0x1005] == nil)
    }

    @Test func operandSideBufferIndexing() {
        let raw = bytes(of: [0xD503_201F, 0x9100_0400])
        let stream = InstructionStream(bytes: raw, at: 0)
        let nop = stream.records[0]
        let add = stream.records[1]
        #expect(stream.operands(for: nop).isEmpty)
        let addOperands = stream.operands(for: add)
        #expect(addOperands.count == 3)
        #expect(stream.operands.count == 3)
        var sawRegister = false
        if case .register = addOperands.first {
            sawRegister = true
        }
        #expect(sawRegister)
    }
}

/// Validates the caller-provided data-in-code seam: covered words become
/// DataMarker records, spans beginning mid-word still mark their word,
/// and each intersecting span is echoed as exactly one diagnostic.
@Suite struct DataInCodeTests {
    private let threeNops: [UInt32] = [0xD503_201F, 0xD503_201F, 0xD503_201F]

    @Test func alignedSpanMarksItsWords() {
        let span = DataInCodeSpan(offset: 4, length: 4, kind: .data)
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0x1000, dataInCode: [span],
        )
        #expect(stream.records.count == 3)
        #expect(stream.records[0].mnemonic == .nop)
        #expect(stream.records[1].mnemonic == .dataMarker)
        #expect(stream.records[1].category == .dataInCodeMarker)
        #expect(stream.records[1].encoding == 0xD503_201F)
        #expect(stream.records[2].mnemonic == .nop)
        #expect(stream.diagnostics.count == 1)
        let diagnostic = stream.diagnostics[0]
        #expect(diagnostic.kind == .dataInCodeSpanEncountered(kind: .data, offset: 4, length: 4))
        #expect(diagnostic.bufferOffset == 4)
    }

    @Test func midWordSpanStillMarksTheWord() {
        let span = DataInCodeSpan(offset: 6, length: 1, kind: .jumpTable8)
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: [span],
        )
        #expect(stream.records[0].mnemonic == .nop)
        #expect(stream.records[1].mnemonic == .dataMarker)
        #expect(stream.records[2].mnemonic == .nop)
        #expect(stream.diagnostics.count == 1)
        #expect(stream.diagnostics[0].kind == .dataInCodeSpanEncountered(kind: .jumpTable8, offset: 6, length: 1))
    }

    @Test func spanCrossingWordBoundaryMarksBothWords() {
        let span = DataInCodeSpan(offset: 3, length: 2, kind: .jumpTable32)
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: [span],
        )
        #expect(stream.records[0].mnemonic == .dataMarker)
        #expect(stream.records[1].mnemonic == .dataMarker)
        #expect(stream.records[2].mnemonic == .nop)
    }

    @Test func nonIntersectingSpanIsIgnored() {
        let span = DataInCodeSpan(offset: 64, length: 8, kind: .data)
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: [span],
        )
        #expect(stream.records.allSatisfy { $0.mnemonic == .nop })
        #expect(stream.diagnostics.isEmpty)
    }

    @Test func unsortedSpansAreSortedForDiagnostics() {
        let spans = [
            DataInCodeSpan(offset: 8, length: 4, kind: .jumpTable16),
            DataInCodeSpan(offset: 0, length: 4, kind: .data),
        ]
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: spans,
        )
        #expect(stream.records[0].mnemonic == .dataMarker)
        #expect(stream.records[1].mnemonic == .nop)
        #expect(stream.records[2].mnemonic == .dataMarker)
        #expect(stream.diagnostics.count == 2)
        #expect(stream.diagnostics[0].bufferOffset == 0)
        #expect(stream.diagnostics[1].bufferOffset == 8)
    }

    @Test func zeroLengthMidWordSpanStillMarksItsWord() {
        // Faithful port pin: the inherited intersection arithmetic marks
        // the containing word for a zero-length span that begins strictly
        // inside it (offset not word-aligned), and echoes the span as a
        // diagnostic with its provided zero length.
        let span = DataInCodeSpan(offset: 5, length: 0, kind: .data)
        let stream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: [span],
        )
        #expect(stream.records[0].mnemonic == .nop)
        #expect(stream.records[1].mnemonic == .dataMarker)
        #expect(stream.records[2].mnemonic == .nop)
        #expect(stream.diagnostics.count == 1)
        #expect(stream.diagnostics[0].kind == .dataInCodeSpanEncountered(kind: .data, offset: 5, length: 0))
        // A zero-length span at a word boundary marks nothing.
        let boundary = DataInCodeSpan(offset: 4, length: 0, kind: .data)
        let boundaryStream = InstructionStream(
            bytes: bytes(of: threeNops), at: 0, dataInCode: [boundary],
        )
        #expect(boundaryStream.records.allSatisfy { $0.mnemonic == .nop })
    }

    @Test func kindRawValuesMirrorLoaderConstants() {
        #expect(DataInCodeSpan.Kind.data.rawValue == 0x0001)
        #expect(DataInCodeSpan.Kind.jumpTable8.rawValue == 0x0002)
        #expect(DataInCodeSpan.Kind.jumpTable16.rawValue == 0x0003)
        #expect(DataInCodeSpan.Kind.jumpTable32.rawValue == 0x0004)
        #expect(DataInCodeSpan.Kind.absoluteJumpTable32.rawValue == 0x0005)
        #expect(DataInCodeSpan.Kind(rawValue: 0x0003) == .jumpTable16)
        #expect(DataInCodeSpan.Kind(rawValue: 0x7777) == .unknown(rawValue: 0x7777))
        #expect(DataInCodeSpan.Kind(rawValue: 0x7777).rawValue == 0x7777)
    }
}

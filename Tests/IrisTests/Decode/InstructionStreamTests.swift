// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import Testing

/// Validates InstructionStream — memberwise init, lookups,
/// and the bytes-in decoding init's edge paths.
@Suite("InstructionStream / memberwise init and lookup")
struct InstructionStreamMemberwiseTests {
    @Test func emptyStreamHasNoRecords() {
        let stream = InstructionStream(
            baseAddress: 0x1_0000_0000,
            byteCount: 0,
            features: [],
            records: [],
            operands: [],
            diagnostics: [],
        )
        #expect(stream.records.isEmpty)
        #expect(stream.operands.isEmpty)
        #expect(stream.diagnostics.isEmpty)
        #expect(stream.baseAddress == 0x1_0000_0000)
        #expect(stream.byteCount == 0)
        #expect(stream[address: 0x1_0000_0000] == nil)
    }

    @Test func lookupAtBaseReturnsFirstRecord() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream[address: 0x1000]?.address == 0x1000)
        #expect(stream[address: 0x1004]?.address == 0x1004)
        #expect(stream[address: 0x100C]?.address == 0x100C)
    }

    @Test func lookupAtUnalignedAddressReturnsNil() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream[address: 0x1001] == nil)
        #expect(stream[address: 0x1003] == nil)
        #expect(stream[address: 0x1007] == nil)
    }

    @Test func lookupAtAddressBelowBaseReturnsNil() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream[address: 0xFFC] == nil)
        #expect(stream[address: 0] == nil)
    }

    @Test func lookupAtAddressPastEndReturnsNil() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream[address: 0x1010] == nil)
        #expect(stream[address: 0x10000] == nil)
    }

    @Test func recordContainingAcceptsUnalignedAddress() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream.instruction(containing: 0x1001)?.address == 0x1000)
        #expect(stream.instruction(containing: 0x1003)?.address == 0x1000)
        #expect(stream.instruction(containing: 0x1007)?.address == 0x1004)
    }

    @Test func recordContainingPastEndReturnsNil() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream.instruction(containing: 0x1010) == nil)
    }

    @Test func recordContainingBelowBaseReturnsNil() {
        let stream = makeManualStream(baseAddress: 0x1000, recordCount: 4)
        #expect(stream.instruction(containing: 0xFFC) == nil)
    }

    @Test func recordAtAndSubscriptAreEquivalent() {
        let stream = makeManualStream(baseAddress: 0x2000, recordCount: 3)
        for i in 0 ..< 3 {
            let addr = UInt64(0x2000 + i * 4)
            #expect(stream.instruction(at: addr) == stream[address: addr])
        }
    }

    @Test func operandsForRecordReturnsCorrectSlice() {
        let r0 = makeUndefinedRecord(address: 0x3000, operandStart: 0, operandCount: 2)
        let r1 = makeUndefinedRecord(address: 0x3004, operandStart: 2, operandCount: 1)
        let ops: [Operand] = [
            .register(RegisterRef.x(0)),
            .register(RegisterRef.x(1)),
            .immediate(value: 42, width: 8),
        ]
        let stream = InstructionStream(
            baseAddress: 0x3000,
            byteCount: 8,
            features: [],
            records: [r0, r1],
            operands: ops,
            diagnostics: [],
        )
        let r0Ops = stream.operands(for: r0)
        #expect(r0Ops.count == 2)
        #expect(r0Ops.first == .register(RegisterRef.x(0)))
        let r1Ops = stream.operands(for: r1)
        #expect(r1Ops.count == 1)
        #expect(r1Ops.first == .immediate(value: 42, width: 8))
    }

    @Test func recordAtReturnsNilWhenRecordsArrayIsShorterThanByteCount() {
        // Manually-built stream with mismatched bookkeeping —
        // sectionByteCount says 16 bytes (4 words) but records has
        // only 1 entry. `record(at:)` must still return nil for words
        // 2..4 rather than crash on an out-of-bounds index.
        let r0 = makeUndefinedRecord(address: 0x5000, operandStart: 0, operandCount: 0)
        let stream = InstructionStream(
            baseAddress: 0x5000,
            byteCount: 16,
            features: [],
            records: [r0],
            operands: [],
            diagnostics: [],
        )
        #expect(stream[address: 0x5000]?.record == r0)
        #expect(stream[address: 0x5004] == nil)
        #expect(stream.instruction(containing: 0x5005) == nil)
    }

    @Test func operandsForRecordOutOfBoundsReturnsEmptySlice() {
        let r = makeUndefinedRecord(address: 0x4000, operandStart: 100, operandCount: 5)
        let stream = InstructionStream(
            baseAddress: 0x4000,
            byteCount: 4,
            features: [],
            records: [r],
            operands: [],
            diagnostics: [],
        )
        let ops = stream.operands(for: r)
        #expect(ops.isEmpty)
    }
}

/// Validates the bytes-in `InstructionStream.init` edge paths —
/// empty buffer, per-word address wrap near 2^64, and bulk decode of
/// real instruction words with lookup parity.
@Suite("InstructionStream / bytes-in init edge paths")
struct InstructionStreamInitTests {
    @Test func emptyBufferProducesEmptyStream() {
        let stream = InstructionStream(bytes: [], at: 0x1_0000_0000)
        #expect(stream.records.isEmpty)
        #expect(stream.operands.isEmpty)
        #expect(stream.baseAddress == 0x1_0000_0000)
        #expect(stream.byteCount == 0)
    }

    @Test func baseAddressNearMaxWrapsPerWordAddresses() {
        // The bytes-in init is total: per-word addresses are
        // baseAddress + offset modulo 2^64, lookup uses the same modular
        // arithmetic (every record is reachable at exactly the address
        // it carries), and the wrap is surfaced once as a diagnostic
        // carrying the first wrapped record's buffer offset.
        // Pathological input only; pinned so drift is visible.
        let base = UInt64.max - 2
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 16),
            at: base,
        )
        #expect(stream.records.count == 4)
        #expect(stream.records[0].address == base)
        // base &+ 4 wraps past 2^64 to 1.
        #expect(stream.records[1].address == 1)
        #expect(stream.records[2].address == 5)
        #expect(stream.records[3].address == 9)
        // Modular lookup: wrapped records resolve at their own addresses.
        #expect(stream[address: base]?.record == stream.records[0])
        #expect(stream[address: 1]?.record == stream.records[1])
        #expect(stream.instruction(containing: 5)?.record == stream.records[2])
        #expect(stream[address: 9]?.record == stream.records[3])
        // One diagnostic marks the wrap at the first wrapped offset.
        #expect(stream.diagnostics == [Diagnostic(kind: .addressSpaceWrapped(offset: 4))])
    }

    @Test func realInstructionWordsDecodeWithLookupParity() {
        // A real AArch64 function shape (prologue, call, epilogue) fed
        // through the bytes-in init with the standard family set. Every
        // word is a genuine instruction, so no record falls back to the
        // decoder sentinels, and lookup by address matches sequential
        // order — the bulk-decode bookkeeping the old Mach-O __text test
        // proved, minus the Mach-O vehicle.
        let words: [UInt32] = [
            0xA9BF_7BFD, // stp x29, x30, [sp, #-16]!
            0x9100_03FD, // mov x29, sp
            0x9400_0001, // bl +4
            0xD503_201F, // nop
            0xA8C1_7BFD, // ldp x29, x30, [sp], #16
            0xD65F_03C0, // ret
        ]
        let base: UInt64 = 0x1_0000_4000
        let stream = InstructionStream(bytes: bytes(of: words), at: base)
        #expect(stream.records.count == words.count)
        for (i, record) in stream.records.enumerated() {
            #expect(record.address == base &+ UInt64(i * 4))
            #expect(record.encoding == words[i])
            #expect(record.category != .undefined)
            #expect(record.category != .dataInCodeMarker)
            #expect(record.category != .truncatedTail)
            #expect(stream[address: record.address]?.record == record)
        }
    }
}

/// Validates InstructionStream behavior on synthetic byte
/// buffers with controlled contents, data-in-code spans, and
/// truncated tails.
@Suite("InstructionStream / synthetic byte buffers")
struct InstructionStreamSyntheticTests {
    /// Base address standing in for a typical __TEXT vmaddr.
    private static let base: UInt64 = 0x1_0000_0000

    @Test func sectionWithTwoWordsProducesTwoUndefinedRecords() {
        // Two reserved-op0 words (bits[28:25] = 0 in both): byte[3]=0x00
        // and byte[3]=0x40 keep bits[28:25] in the reserved tier {0..3}
        // where no FamilyDecoder is registered. Previously the test used
        // 0xFFFFFFFF which now decodes as a valid FNMSUB under the
        // SIMD/FP family's coverage.
        // word 0 = 0x0200_0000 (op0 = 1, unallocated → UNDEFINED); word 1 =
        // 0x40FF_FFFF (op0 = 0, non-UDF, non-AMX → UNDEFINED). Avoids the
        // UDF encoding (0x0000_NNNN) so both words are genuinely undefined.
        let stream = InstructionStream(
            bytes: [0x00, 0x00, 0x00, 0x02, 0xFF, 0xFF, 0xFF, 0x40],
            at: Self.base,
        )
        #expect(stream.records.count == 2)
        #expect(stream.records[0].address == Self.base)
        #expect(stream.records[1].address == Self.base &+ 4)
        // ARM64 is little-endian; record.encoding reads bytes as LE u32.
        #expect(stream.records[0].encoding == 0x0200_0000)
        #expect(stream.records[1].encoding == 0x40FF_FFFF)
        for record in stream.records {
            #expect(record.category == .undefined)
        }
    }

    @Test func sectionWithSevenBytesProducesOneWordAndOneTruncatedTail() {
        let bytes: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11]
        let stream = InstructionStream(bytes: bytes, at: Self.base)
        #expect(stream.records.count == 2)
        #expect(stream.records[0].category == .undefined)
        #expect(stream.records[0].encoding == 0xDDCC_BBAA)
        let tail = stream.records[1]
        #expect(tail.category == .truncatedTail)
        #expect(tail.mnemonic == .truncatedTail)
        // Residual bytes 0xEE 0xFF 0x11 packed LE-low.
        #expect(tail.encoding == 0x0011_FFEE)
        // operandCount carries the residual byte count on tails; the
        // operand window itself is still empty.
        #expect(tail.operandCount == 3)
        #expect(tail.tailByteCount == 3)
        #expect(stream.operands(for: tail).isEmpty)
    }

    @Test func truncationProducesCorrectTailForEverySectionSizeOneThroughSeven() throws {
        // Stream-level truncation across every interesting residual
        // length, not just the 3-byte case. Sizes 1/2/3 (no prefix
        // words), 5/6/7 (one prefix word + tail).
        struct Expectation {
            let size: Int
            let recordCount: Int
            let prefixEncoding: UInt32?
            let tailEncoding: UInt32
            let tailRelativeAddress: UInt64
        }
        let bytes: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11]
        let expectations: [Expectation] = [
            Expectation(size: 1, recordCount: 1, prefixEncoding: nil, tailEncoding: 0x0000_00AA, tailRelativeAddress: 0),
            Expectation(size: 2, recordCount: 1, prefixEncoding: nil, tailEncoding: 0x0000_BBAA, tailRelativeAddress: 0),
            Expectation(size: 3, recordCount: 1, prefixEncoding: nil, tailEncoding: 0x00CC_BBAA, tailRelativeAddress: 0),
            Expectation(size: 5, recordCount: 2, prefixEncoding: 0xDDCC_BBAA, tailEncoding: 0x0000_00EE, tailRelativeAddress: 4),
            Expectation(size: 6, recordCount: 2, prefixEncoding: 0xDDCC_BBAA, tailEncoding: 0x0000_FFEE, tailRelativeAddress: 4),
            Expectation(size: 7, recordCount: 2, prefixEncoding: 0xDDCC_BBAA, tailEncoding: 0x0011_FFEE, tailRelativeAddress: 4),
        ]
        for exp in expectations {
            let stream = InstructionStream(
                bytes: Array(bytes.prefix(exp.size)),
                at: Self.base,
            )
            #expect(stream.records.count == exp.recordCount, "size=\(exp.size)")
            if let prefix = exp.prefixEncoding {
                #expect(stream.records[0].category == .undefined, "size=\(exp.size)")
                #expect(stream.records[0].encoding == prefix, "size=\(exp.size)")
            }
            let tail = try #require(stream.records.last)
            #expect(tail.category == .truncatedTail, "size=\(exp.size)")
            #expect(tail.encoding == exp.tailEncoding, "size=\(exp.size)")
            #expect(tail.address == Self.base &+ exp.tailRelativeAddress, "size=\(exp.size)")
            // operandCount carries the residual byte count on tails; the
            // operand window itself is still empty.
            #expect(tail.operandCount == UInt8(exp.size % 4), "size=\(exp.size)")
            #expect(tail.tailByteCount == exp.size % 4, "size=\(exp.size)")
            #expect(stream.operands(for: tail).isEmpty, "size=\(exp.size)")
            // High bits beyond residual must be zero.
            let residualBytes = exp.size % 4
            let highMask: UInt32 = (residualBytes == 3) ? 0xFF00_0000 : (residualBytes == 2 ? 0xFFFF_0000 : 0xFFFF_FF00)
            #expect((tail.encoding & highMask) == 0, "high bits non-zero size=\(exp.size)")
        }
    }

    @Test func streamInitCommitsOperandBufferAndClassBits() {
        // End-to-end stream construction over real instructions with
        // operands. Verifies operand-buffer commit, the
        // operandStart/operandCount accounting across consecutive
        // records, and the class-bit round-trip through commit.
        // ADD x0, x0, #1 (3 operands) ×2, then ADDS x1, x2, #2 (NZCV).
        let bytes: [UInt8] = [
            0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
            0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
            0x41, 0x08, 0x00, 0xB1, // adds x1, x2, #2
        ]
        let stream = InstructionStream(bytes: bytes, at: Self.base)
        #expect(stream.records.count == 3)
        for record in stream.records {
            #expect(record.category == .dataProcessingImmediate)
        }
        // operandStart progresses by each record's operandCount.
        #expect(stream.records[0].operandStart == 0)
        #expect(stream.records[0].operandCount == 3)
        #expect(stream.records[1].operandStart == 3)
        #expect(stream.records[1].operandCount == 3)
        #expect(stream.records[2].operandStart == 6)
        #expect(stream.records[2].operandCount == 3)
        #expect(stream.operands.count == 9)
        // Per-record operand slices land on each record's own window.
        #expect(stream.operands(for: stream.records[0]).first == .register(.x(0)))
        #expect(stream.operands(for: stream.records[2]).first == .register(.x(1)))
        // Class bits round-tripped through commit.
        #expect(stream.records[2].flagEffect == .nzcv)
        #expect(stream.records[2].mnemonic == .adds)
    }

    @Test func dataInCodeSpanProducesDataMarkerRecords() {
        // Word 2 (0x40BBAA99) uses byte[3]=0x40 so bits[28:25] = 0000 =
        // op0=0 (reserved tier, no decoder registered) — the
        // dispatcher emits UNDEFINED. (Was 0xCC=op0=6, but with the
        // L/S→SIMD/FP delegation that encoding decodes as a NEON ST1.)
        let bytes: [UInt8] = [
            0x11, 0x22, 0x33, 0x44, // word 0 — will be inside DIC span
            0x55, 0x66, 0x77, 0x88, // word 1 — will be inside DIC span
            0x99, 0xAA, 0xBB, 0x40, // word 2 — outside DIC span; reserved op0=0
        ]
        let stream = InstructionStream(
            bytes: bytes,
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 0, length: 8, kind: .data)],
        )
        #expect(stream.records.count == 3)
        #expect(stream.records[0].category == .dataInCodeMarker)
        #expect(stream.records[0].mnemonic == .dataMarker)
        #expect(stream.records[1].category == .dataInCodeMarker)
        #expect(stream.records[2].category == .undefined)
        // Encoding must preserve the original word bytes even on a
        // dataMarker record — the stream doesn't reinterpret data bytes.
        #expect(stream.records[0].encoding == 0x4433_2211)
        #expect(stream.records[1].encoding == 0x8877_6655)
        #expect(stream.records[2].encoding == 0x40BB_AA99)
    }

    @Test func dataInCodeSpanWithOverflowingLengthClampsToTheBufferEnd() {
        // offset + length overflowing UInt64 saturates the span end; the
        // span still marks every word from its start to the buffer end.
        let bytes: [UInt8] = [
            0x1F, 0x20, 0x03, 0xD5, // word 0 — nop, outside the span
            0x11, 0x22, 0x33, 0x44, // word 1 — inside the overflowing span
        ]
        let stream = InstructionStream(
            bytes: bytes,
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 4, length: UInt64.max, kind: .data)],
        )
        #expect(stream.records.count == 2)
        #expect(stream.records[0].mnemonic == .nop)
        #expect(stream.records[1].category == .dataInCodeMarker)
    }

    @Test func dataInCodeSpanEmitsDiagnosticCarryingKind() {
        let stream = InstructionStream(
            bytes: Array(repeating: 0, count: 16),
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 4, length: 4, kind: .jumpTable16)],
        )
        // The stream emits exactly one diagnostic kind, so assert
        // the expected payload directly rather than pattern-matching
        // (which would generate a dead nil-return branch).
        let expectedKind: Diagnostic.Kind = .dataInCodeSpanEncountered(
            kind: .jumpTable16,
            offset: 4,
            length: 4,
        )
        #expect(stream.diagnostics.map(\.kind).contains(expectedKind))
    }

    @Test func dicDiagnosticCarriesEveryKindWithOffsetAndLength() {
        // Parameterize over every documented kind plus an unknown raw
        // value, asserting the diagnostic preserves offset and
        // length as well as kind. Each stream uses a single span so
        // the test is per-kind atomic.
        let kindRaws: [(raw: UInt16, expected: DataInCodeSpan.Kind)] = [
            (0x0001, .data),
            (0x0002, .jumpTable8),
            (0x0003, .jumpTable16),
            (0x0004, .jumpTable32),
            (0x0005, .absoluteJumpTable32),
            (0xABCD, .unknown(rawValue: 0xABCD)),
        ]
        for (kindRaw, expectedKind) in kindRaws {
            let stream = InstructionStream(
                bytes: Array(repeating: UInt8(0), count: 16),
                at: Self.base,
                dataInCode: [DataInCodeSpan(offset: 4, length: 4, kind: .init(rawValue: kindRaw))],
            )
            // Same shape as the single-kind test: direct equality on
            // the diagnostic's `kind`, no pattern-match closures.
            let expected: Diagnostic.Kind = .dataInCodeSpanEncountered(
                kind: expectedKind,
                offset: 4,
                length: 4,
            )
            let matches = stream.diagnostics.map(\.kind).filter { $0 == expected }
            #expect(matches.count == 1,
                    "expected exactly one DIC diagnostic matching \(expected) for raw=0x\(String(kindRaw, radix: 16))")
        }
    }

    @Test func zeroLengthDataInCodeSpanDoesNotMarkAnyWord() {
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 8),
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 4, length: 0, kind: .data)],
        )
        #expect(stream.records.count == 2)
        // Zero-length span: spanEnd == spanStart, so `wordStart
        // < spanEnd` is never true. No marker.
        #expect(stream.records[0].category == .undefined)
        #expect(stream.records[1].category == .undefined)
    }

    @Test func dataInCodeSpanStartingAtSectionEndDoesNotMark() {
        // Span starts at offset 8 (== bytes.count, == buffer end);
        // does not intersect any in-buffer word.
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 8),
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 8, length: 4, kind: .data)],
        )
        #expect(stream.records.count == 2)
        #expect(stream.records[0].category == .undefined)
        #expect(stream.records[1].category == .undefined)
    }

    @Test func dataInCodeSpanStraddlingSectionEndMarksOnlyInSectionWords() {
        // Span starts at offset 6, length 8 → covers bytes 6..13.
        // Buffer ends at byte 8, so the span intersects bytes 6..7
        // (inside word 1) — that one word should be marked.
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 8),
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 6, length: 8, kind: .data)],
        )
        #expect(stream.records.count == 2)
        #expect(stream.records[0].category == .undefined)
        #expect(stream.records[1].category == .dataInCodeMarker)
    }

    @Test func overlappingDataInCodeSpansBothMarkTheirWords() {
        // Two spans both covering word 1 (bytes 4..7) — overlap test.
        // First span also covers word 0; second also covers word 2.
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 16),
            at: Self.base,
            dataInCode: [
                DataInCodeSpan(offset: 0, length: 8, kind: .data),
                DataInCodeSpan(offset: 4, length: 8, kind: .jumpTable8),
            ],
        )
        #expect(stream.records.count == 4)
        #expect(stream.records[0].category == .dataInCodeMarker)
        #expect(stream.records[1].category == .dataInCodeMarker)
        #expect(stream.records[2].category == .dataInCodeMarker)
        #expect(stream.records[3].category == .undefined)
    }

    @Test func multipleUnsortedDataInCodeSpansAreCorrectlyOrdered() {
        // Two DIC spans deliberately listed in reverse-offset order to
        // force the sort comparator inside `filteredIntersectingSpans`
        // to fire. The stream must classify each intersecting word
        // correctly regardless of input order.
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 16),
            at: Self.base,
            dataInCode: [
                DataInCodeSpan(offset: 12, length: 4, kind: .jumpTable8), // word 3 — listed FIRST (high offset)
                DataInCodeSpan(offset: 0, length: 4, kind: .data), // word 0 — listed SECOND (low offset)
            ],
        )
        #expect(stream.records[0].category == .dataInCodeMarker)
        #expect(stream.records[1].category == .undefined)
        #expect(stream.records[2].category == .undefined)
        #expect(stream.records[3].category == .dataInCodeMarker)
    }

    @Test func midWordDataInCodeSpanMarksTheWholeWord() {
        // Span starts at byte 6, length 4 → covers bytes 6..9, which
        // intersects word at offset 4 (bytes 4..7) AND word at offset 8
        // (bytes 8..11).
        let stream = InstructionStream(
            bytes: undefinedFiller(byteCount: 16),
            at: Self.base,
            dataInCode: [DataInCodeSpan(offset: 6, length: 4, kind: .data)],
        )
        #expect(stream.records.count == 4)
        // Word 0 (bytes 0..3) — outside the span.
        #expect(stream.records[0].category == .undefined)
        // Word 1 (bytes 4..7) — intersects span (span starts at 6).
        #expect(stream.records[1].category == .dataInCodeMarker)
        // Word 2 (bytes 8..11) — intersects span (span ends at 10).
        #expect(stream.records[2].category == .dataInCodeMarker)
        // Word 3 (bytes 12..15) — outside the span.
        #expect(stream.records[3].category == .undefined)
    }
}

/// Validates InstructionStream's RandomAccessCollection conformance —
/// Element is Instruction, Index is Int, the truncated-tail record is
/// an ordinary element, and the labeled address subscript coexists with
/// the element-index subscript without ambiguity.
@Suite("InstructionStream / collection of Instruction values")
struct InstructionStreamCollectionTests {
    @Test func streamIteratesAsInstructions() {
        let bytes: [UInt8] = [
            0x1F, 0x20, 0x03, 0xD5, // nop
            0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ]
        let stream = InstructionStream(bytes: bytes, at: 0x1000)
        #expect(stream.count == 3)
        #expect(stream.count == stream.records.count)
        var mnemonics: [Mnemonic] = []
        for instruction in stream {
            mnemonics.append(instruction.mnemonic)
        }
        #expect(mnemonics == [.nop, .add, .ret])
        // Element-index subscript and record array agree.
        #expect(stream[1].record == stream.records[1])
        #expect(stream[1].operands.count == 3)
        // map / filter behave like any collection.
        #expect(stream.map(\.address) == [0x1000, 0x1004, 0x1008])
        #expect(stream.count(where: { $0.mnemonic == .add }) == 1)
    }

    @Test func indexAndAddressSubscriptsAreDistinct() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5], at: 0x1000)
        // Element index 0 vs address 0x1000 resolve the same instruction
        // through different doors; an address literal cannot reach the
        // Int subscript because the address form is labeled.
        #expect(stream[0] == stream[address: 0x1000])
        #expect(stream.startIndex == 0)
        #expect(stream.endIndex == 1)
    }

    @Test func truncatedTailIsAnOrdinaryElementWithEmptyOperands() {
        let stream = InstructionStream(bytes: [0x1F, 0x20, 0x03, 0xD5, 0xAB, 0xCD], at: 0)
        #expect(stream.count == 2)
        let tail = stream[1]
        #expect(tail.category == .truncatedTail)
        #expect(tail.operands.isEmpty)
        #expect(tail.record.tailByteCount == 2)
        // n/4 + 1 element shape: 6 bytes -> 1 word + 1 tail.
        #expect(stream.last?.category == .truncatedTail)
    }

    @Test func instructionLookupsReturnViewsOverTheStream() {
        let stream = InstructionStream(bytes: [0x00, 0x04, 0x00, 0x91], at: 0x2000)
        let viaAt = stream.instruction(at: 0x2000)
        let viaContaining = stream.instruction(containing: 0x2002)
        let viaSubscript = stream[address: 0x2000]
        #expect(viaAt == viaContaining)
        #expect(viaAt == viaSubscript)
        #expect(viaAt?.operands.count == 3)
        #expect(viaAt?.record == stream.records[0])
    }
}

private func makeManualStream(baseAddress: UInt64, recordCount: Int) -> InstructionStream {
    let records = (0 ..< recordCount).map {
        makeUndefinedRecord(
            address: baseAddress &+ UInt64($0 * 4),
            operandStart: 0,
            operandCount: 0,
        )
    }
    return InstructionStream(
        baseAddress: baseAddress,
        byteCount: UInt64(recordCount * 4),
        features: [],
        records: records,
        operands: [],
        diagnostics: [],
    )
}

private func makeUndefinedRecord(address: UInt64, operandStart: UInt32, operandCount: UInt8) -> InstructionRecord {
    InstructionRecord(
        address: address,
        semanticReads: .empty,
        semanticWrites: .empty,
        encoding: 0,
        operandStart: operandStart,
        mnemonic: .undefined,
        branchClass: .none,
        memoryAccess: .none,
        memoryOrdering: [],
        flagEffect: .none,
        category: .undefined,
        operandCount: operandCount,
    )
}

/// Buffer filler whose every 4-byte word is `0x0200_0000` (op0 = 1,
/// architecturally unallocated → UNDEFINED), so data-in-code tests can assert
/// non-marked words are `.undefined` without colliding with UDF
/// (`0x0000_NNNN`), which the decoder recognizes as a real instruction.
private func undefinedFiller(byteCount: Int) -> [UInt8] {
    let word: [UInt8] = [0x00, 0x00, 0x00, 0x02] // 0x0200_0000 little-endian
    return (0 ..< byteCount).map { word[$0 % 4] }
}

/// Little-endian byte serialization of instruction words.
private func bytes(of words: [UInt32]) -> [UInt8] {
    var out: [UInt8] = []
    out.reserveCapacity(words.count * 4)
    for word in words {
        out.append(UInt8(truncatingIfNeeded: word))
        out.append(UInt8(truncatingIfNeeded: word >> 8))
        out.append(UInt8(truncatingIfNeeded: word >> 16))
        out.append(UInt8(truncatingIfNeeded: word >> 24))
    }
    return out
}

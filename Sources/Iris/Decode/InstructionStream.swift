// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// InstructionStream. The address-indexed record buffer for one
// contiguous code range. Construction takes raw code bytes (plus base
// address, features, and caller-provided data-in-code spans), dispatches
// each 4-byte word through the family-decoder table, and emits a
// truncated-tail record for the residual when the byte count is not a
// multiple of 4. Word reads assemble little-endian explicitly, so
// behavior is identical on any host byte order.

/// Contiguous address-indexed stream of decoded ARM64 instructions
/// produced from a single code buffer.
///
/// Records are stored in a flat array; address-to-record lookup is the
/// constant-time arithmetic `(address - baseAddress) / 4`, evaluated
/// modulo 2^64 (see the address model below). The `operands` array is
/// the side buffer indexed by each record's `operandStart`/`operandCount`;
/// most records carry operands there, while UNDEFINED, data-marker, and
/// truncated-tail records carry none.
///
/// **Address model.** Per-word addresses are `baseAddress + offset`
/// modulo 2^64. For a `baseAddress` near the top of the address space
/// the addresses of later words wrap past zero; decode stays total,
/// lookup uses the same modular arithmetic (every record is reachable
/// at exactly the address it carries), and construction surfaces the
/// wrap once via ``Diagnostic/Kind/addressSpaceWrapped(offset:)``.
@frozen
public struct InstructionStream: Sendable, RandomAccessCollection {
    /// VM base address of the buffer this stream was constructed from.
    public let baseAddress: UInt64
    /// Byte length of the buffer this stream was constructed from.
    public let byteCount: UInt64
    /// The instruction-set extensions this stream was decoded with —
    /// stored so the stream is self-describing provenance: decode is a
    /// pure function of (bytes, base address, features, data-in-code
    /// spans), and three of the four inputs are recoverable from the
    /// value itself.
    public let features: Features
    /// One record per 4-byte word, plus one trailing record for the
    /// residual 1-3 bytes if `byteCount % 4 != 0`.
    public let records: [InstructionRecord]
    /// Flat operand buffer. Each record's operands are at
    /// `operands[record.operandStart ..< record.operandStart + record.operandCount]`.
    public let operands: [Operand]
    /// Stream-emitted diagnostics encountered during construction.
    public let diagnostics: [Diagnostic]

    // Collection conformance: a stream is a random-access collection of
    // Instruction values, one per record (the truncated-tail record is
    // an ordinary element). Forming an element is a 40-byte record copy
    // plus an operand view over the shared buffer — zero heap allocation.

    public typealias Element = Instruction
    public typealias Index = Int

    /// Always 0.
    @inlinable
    public var startIndex: Int {
        0
    }

    /// One past the last record; `count == records.count`.
    @inlinable
    public var endIndex: Int {
        records.count
    }

    /// The instruction at element index `position` (not an address —
    /// address lookup is the labeled ``subscript(address:)``).
    @inlinable
    public subscript(position: Int) -> Instruction {
        let record = records[position]
        return Instruction(record: record, operands: operands(for: record))
    }

    @inlinable
    public init(
        baseAddress: UInt64,
        byteCount: UInt64,
        features: Features,
        records: [InstructionRecord],
        operands: [Operand],
        diagnostics: [Diagnostic],
    ) {
        self.baseAddress = baseAddress
        self.byteCount = byteCount
        self.features = features
        self.records = records
        self.operands = operands
        self.diagnostics = diagnostics
    }

    /// Build a stream by decoding every 4-byte word in `bytes`.
    ///
    /// Decode is a pure function of its arguments: an empty buffer
    /// yields an empty stream; a trailing 1-3 byte residual yields one
    /// truncated-tail record; every word covered by a `dataInCode` span
    /// (including a span beginning mid-word) becomes a data-marker record
    /// and each intersecting span is echoed as one stream diagnostic.
    /// Per-word addresses are `baseAddress` plus the word's buffer
    /// offset, modulo 2^64; if any record's address wraps past zero, one
    /// ``Diagnostic/Kind/addressSpaceWrapped(offset:)`` diagnostic marks
    /// the first wrapped record's buffer offset.
    ///
    /// - Parameters:
    ///   - bytes: raw code bytes, little-endian ARM64 words.
    ///   - baseAddress: VM address of `bytes[0]`.
    ///   - features: instruction-set extensions to decode; the empty set
    ///     is plain ARM64.
    ///   - dataInCode: spans of `bytes` that are data, not instructions,
    ///     in buffer-offset space.
    public init(
        bytes: UnsafeRawBufferPointer,
        at baseAddress: UInt64 = 0,
        features: Features = [],
        dataInCode: [DataInCodeSpan] = [],
    ) {
        let byteCount = UInt64(bytes.count)
        let wordCount = bytes.count / 4
        let residual = bytes.count % 4
        let totalRecords = wordCount &+ (residual > 0 ? 1 : 0)

        // Empty buffer: zero-record stream.
        if totalRecords == 0 {
            self.init(
                baseAddress: baseAddress,
                byteCount: byteCount,
                features: features,
                records: [],
                operands: [],
                diagnostics: [],
            )
            return
        }

        // Pre-build the data-in-code intersector: only spans that
        // intersect the buffer's byte range, sorted by start. The
        // per-word loop advances a cursor through this filtered array,
        // achieving O(words + filteredSpans) instead of
        // O(words * log(spans)) with the naive lookup. The intersection
        // check also correctly handles unaligned spans (a span
        // beginning mid-word still marks the word as data).
        let intersectingSpans = InstructionStream.filteredIntersectingSpans(
            dataInCode,
            byteCount: byteCount,
        )

        var records: [InstructionRecord] = []
        records.reserveCapacity(totalRecords)
        var operandBuffer: [Operand] = []
        var diagnostics: [Diagnostic] = []
        // The span kind is preserved on the stream's diagnostics. Emit
        // one informational diagnostic per intersecting span (not per
        // word — keeps the diagnostic count proportional to the number
        // of spans, not records).
        for span in intersectingSpans {
            diagnostics.append(Diagnostic(
                kind: .dataInCodeSpanEncountered(
                    kind: span.kind,
                    offset: span.start,
                    length: span.length,
                ),
            ))
        }

        // Address-wrap surfacing (computed once, no per-word cost):
        // record offsets are multiples of 4, and `baseAddress &+ offset`
        // wraps past zero exactly when `offset >= (0 &- baseAddress)`.
        // Emit one diagnostic carrying the first wrapped record offset.
        if baseAddress > 0 {
            let wrapThreshold = 0 &- baseAddress
            let lastRecordOffset = UInt64(totalRecords &- 1) &* 4
            if wrapThreshold <= lastRecordOffset {
                let firstWrappedOffset = (wrapThreshold &+ 3) & ~UInt64(3)
                diagnostics.append(Diagnostic(
                    kind: .addressSpaceWrapped(offset: firstWrappedOffset),
                ))
            }
        }

        InstructionStream.decodeAlignedPrefix(
            wordCount: wordCount,
            baseAddress: baseAddress,
            bytes: bytes,
            intersectingSpans: intersectingSpans,
            features: features,
            into: &records,
            operands: &operandBuffer,
        )

        if residual > 0 {
            InstructionStream.appendTruncatedTail(
                residual: residual,
                tailOffset: wordCount &* 4,
                tailAddress: baseAddress &+ UInt64(wordCount &* 4),
                bytes: bytes,
                operandsCount: operandBuffer.count,
                into: &records,
            )
        }

        self.init(
            baseAddress: baseAddress,
            byteCount: byteCount,
            features: features,
            records: records,
            operands: operandBuffer,
            diagnostics: diagnostics,
        )
    }

    /// Build a stream by decoding every 4-byte word in `bytes`.
    /// Array-convenience form of
    /// ``init(bytes:at:features:dataInCode:)-(UnsafeRawBufferPointer,_,_,_)``.
    public init(
        bytes: [UInt8],
        at baseAddress: UInt64 = 0,
        features: Features = [],
        dataInCode: [DataInCodeSpan] = [],
    ) {
        self = bytes.withUnsafeBytes { raw in
            InstructionStream(
                bytes: raw,
                at: baseAddress,
                features: features,
                dataInCode: dataInCode,
            )
        }
    }

    /// Constant-time address lookup. `address` MUST be the start
    /// address of a 4-byte word — i.e. `(address - baseAddress)` modulo
    /// 2^64 must be a multiple of 4, or equal to
    /// `floor(byteCount / 4) * 4` for the truncated-tail record.
    /// Unaligned addresses and addresses outside the stream return `nil`.
    /// The delta is modular, matching the address model: in a stream
    /// whose addresses wrap past zero, every instruction is reachable at
    /// exactly the address it carries.
    @inlinable
    @inline(__always)
    public func instruction(at address: UInt64) -> Instruction? {
        let delta = address &- baseAddress
        guard delta < byteCount else { return nil }
        guard delta % 4 == 0 else { return nil }
        let index = Int(delta / 4)
        guard index < records.count else { return nil }
        return self[index]
    }

    /// Containing-lookup: returns the instruction whose 4-byte range
    /// covers `address`. Unlike ``instruction(at:)``, this accepts
    /// unaligned addresses (rounding down to the containing word).
    /// Useful for jump-table inspection where a fix-up target may be a
    /// mid-word byte.
    @inlinable
    @inline(__always)
    public func instruction(containing address: UInt64) -> Instruction? {
        let delta = address &- baseAddress
        guard delta < byteCount else { return nil }
        let index = Int(delta / 4)
        guard index < records.count else { return nil }
        return self[index]
    }

    /// Subscript form of ``instruction(at:)``. Labeled, so an address
    /// literal can never silently resolve against the collection's
    /// element-index subscript.
    @inlinable
    @inline(__always)
    public subscript(address address: UInt64) -> Instruction? {
        instruction(at: address)
    }

    /// The operand view for a record. Truncated-tail records have no
    /// operands by contract (their `operandCount` carries the residual
    /// byte count — see ``InstructionRecord/tailByteCount``), so the
    /// tail path forms empty explicitly; hostile hand-built indices
    /// clamp to empty.
    @inlinable
    @inline(__always)
    public func operands(for record: InstructionRecord) -> Instruction.Operands {
        if record.category == .truncatedTail {
            return Instruction.Operands(base: operands, offset: 0, count: 0)
        }
        let lo = Int(record.operandStart)
        let hi = lo &+ Int(record.operandCount)
        if lo >= operands.count || hi > operands.count {
            return Instruction.Operands(base: operands, offset: 0, count: 0)
        }
        return Instruction.Operands(base: operands, offset: lo, count: Int(record.operandCount))
    }

    // Helpers — static functions kept off the public surface.

    /// Filter `spans` to those that intersect the buffer's byte range
    /// `[0, byteCount)` and sort them by `offset`. `end` is the walk
    /// bound `offset + length` saturated at `UInt64.max` (a length that
    /// would wrap past the address space reads as "to the end"), so the
    /// per-word cursor needs no overflow branch; `length` echoes the
    /// span as provided, for the diagnostics.
    private static func filteredIntersectingSpans(
        _ spans: [DataInCodeSpan],
        byteCount: UInt64,
    ) -> [(start: UInt64, end: UInt64, length: UInt64, kind: DataInCodeSpan.Kind)] {
        var out: [(UInt64, UInt64, UInt64, DataInCodeSpan.Kind)] = []
        out.reserveCapacity(spans.count)
        for span in spans {
            let spanStart = span.offset
            let (sum, overflow) = spanStart.addingReportingOverflow(span.length)
            let spanEnd = overflow ? UInt64.max : sum
            if spanStart < byteCount, spanEnd > 0 {
                out.append((spanStart, spanEnd, span.length, span.kind))
            }
        }
        out.sort { $0.0 < $1.0 }
        return out
    }

    /// Decode every word in the aligned prefix `[0, wordCount * 4)`.
    /// Walks the data-in-code intersector in tandem with the word loop;
    /// every word either becomes a data marker (intersects a span) or
    /// is dispatched through the family-decoder table.
    @_optimize(speed)
    private static func decodeAlignedPrefix(
        wordCount: Int,
        baseAddress: UInt64,
        bytes: UnsafeRawBufferPointer,
        intersectingSpans: [(start: UInt64, end: UInt64, length: UInt64, kind: DataInCodeSpan.Kind)],
        features: Features,
        into records: inout [InstructionRecord],
        operands: inout [Operand],
    ) {
        var spanCursor = 0
        for wordIndex in 0 ..< wordCount {
            let byteOffset = wordIndex &* 4
            let wordStart = UInt64(byteOffset)
            let wordEnd = wordStart &+ 4
            let address = baseAddress &+ wordStart

            // Advance cursor past spans that end at or before this
            // word's start.
            while spanCursor < intersectingSpans.count,
                  intersectingSpans[spanCursor].end <= wordStart
            {
                spanCursor &+= 1
            }

            let intersects = spanCursor < intersectingSpans.count
                && intersectingSpans[spanCursor].start < wordEnd
                && wordStart < intersectingSpans[spanCursor].end

            // Explicit little-endian word assembly: ARM64 instruction
            // words are little-endian in memory regardless of host
            // byte order. `wordIndex < wordCount` proves the 4-byte
            // read is in bounds.
            let encoding = UInt32(bytes[byteOffset])
                | (UInt32(bytes[byteOffset &+ 1]) << 8)
                | (UInt32(bytes[byteOffset &+ 2]) << 16)
                | (UInt32(bytes[byteOffset &+ 3]) << 24)
            let draft: DecodedDraft = intersects
                ? .dataMarker(at: address, encoding: encoding)
                : MachineCodeDecoder.dispatch(
                    encoding: encoding,
                    address: address,
                    families: .standard,
                    features: features,
                )

            let operandStart = UInt32(operands.count)
            operands.append(contentsOf: draft.operands)
            records.append(InstructionRecord(
                address: draft.address,
                semanticReads: draft.semanticReads,
                semanticWrites: draft.semanticWrites,
                encoding: draft.encoding,
                operandStart: operandStart,
                mnemonic: draft.mnemonic,
                branchClass: draft.branchClass,
                memoryAccess: draft.memoryAccess,
                memoryOrdering: draft.memoryOrdering,
                flagEffect: draft.flagEffect,
                category: draft.category,
                operandCount: UInt8(truncatingIfNeeded: draft.operands.count),
            ))
        }
    }

    /// Read the 1, 2, or 3 residual bytes and append a truncated-tail
    /// record (residual packed into `encoding` at the low bits, high
    /// bits zero, operands empty, `operandCount` carrying the residual
    /// byte count).
    private static func appendTruncatedTail(
        residual: Int,
        tailOffset: Int,
        tailAddress: UInt64,
        bytes: UnsafeRawBufferPointer,
        operandsCount: Int,
        into records: inout [InstructionRecord],
    ) {
        // Read the residual bytes from the buffer. `tailOffset + residual
        // == bytes.count` by construction, so each read is in bounds.
        var residualBytes: [UInt8] = []
        residualBytes.reserveCapacity(residual)
        for k in 0 ..< residual {
            residualBytes.append(bytes[tailOffset &+ k])
        }
        let tail = ArraySlice(residualBytes)
        let draft = DecodedDraft.truncatedTail(at: tailAddress, residualBytes: tail)
        records.append(InstructionRecord(
            address: draft.address,
            semanticReads: draft.semanticReads,
            semanticWrites: draft.semanticWrites,
            encoding: draft.encoding,
            operandStart: UInt32(operandsCount),
            mnemonic: draft.mnemonic,
            branchClass: draft.branchClass,
            memoryAccess: draft.memoryAccess,
            memoryOrdering: draft.memoryOrdering,
            flagEffect: draft.flagEffect,
            category: draft.category,
            operandCount: UInt8(truncatingIfNeeded: residual),
        ))
    }
}

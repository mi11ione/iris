// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Contiguous address-indexed stream of decoded ARM64 instructions from one
/// code buffer, looked up by the constant-time `(address - baseAddress) / 4`.
///
/// Per-word addresses are modulo 2^64: a base near the top of the space wraps
/// later words past zero, every record stays reachable at the address it
/// carries, and construction reports the wrap once as a diagnostic.
@frozen
public struct InstructionStream: Sendable, RandomAccessCollection {
    /// VM base address of the buffer this stream was constructed from.
    public let baseAddress: UInt64
    /// Byte length of the buffer this stream was constructed from.
    public let byteCount: UInt64
    /// The instruction-set extensions this stream was decoded with.
    public let features: Features
    /// One record per 4-byte word, plus one trailing record for the
    /// residual 1-3 bytes if `byteCount % 4 != 0`.
    public let records: [InstructionRecord]
    /// Flat operand buffer. Each record's operands are at
    /// `operands[record.operandStart ..< record.operandStart + record.operandCount]`.
    public let operands: [Operand]
    /// Stream-emitted diagnostics encountered during construction.
    public let diagnostics: [Diagnostic]

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
    /// A trailing 1-3 byte residual yields one truncated-tail record; every
    /// word a `dataInCode` span covers becomes a data-marker record, each
    /// intersecting span echoed as one diagnostic.
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

        let intersectingSpans = InstructionStream.filteredIntersectingSpans(
            dataInCode,
            byteCount: byteCount,
        )

        var records: [InstructionRecord] = []
        records.reserveCapacity(totalRecords)
        var sink = OperandSink(reservingCapacity: totalRecords * 9 / 4)
        var diagnostics: [Diagnostic] = []
        for span in intersectingSpans {
            diagnostics.append(Diagnostic(
                kind: .dataInCodeSpanEncountered(
                    kind: span.kind,
                    offset: span.start,
                    length: span.length,
                ),
            ))
        }

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
            sink: &sink,
        )

        if residual > 0 {
            InstructionStream.appendTruncatedTail(
                residual: residual,
                tailOffset: wordCount &* 4,
                tailAddress: baseAddress &+ UInt64(wordCount &* 4),
                bytes: bytes,
                operandsCount: sink.mark,
                into: &records,
            )
        }

        self.init(
            baseAddress: baseAddress,
            byteCount: byteCount,
            features: features,
            records: records,
            operands: sink.operands,
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

    /// Constant-time address lookup. `address` must be a record's start
    /// address; unaligned addresses and addresses outside the stream
    /// return `nil`.
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

    /// The instruction whose 4-byte range covers `address`. Unlike
    /// ``instruction(at:)`` this accepts unaligned addresses, rounding
    /// down to the containing word.
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

    /// The operand view for a record. Truncated-tail records and
    /// out-of-range indices form empty.
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

    /// Spans intersecting `[0, byteCount)`, sorted by offset, with `end`
    /// saturated at `UInt64.max`.
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
    @_optimize(speed)
    private static func decodeAlignedPrefix(
        wordCount: Int,
        baseAddress: UInt64,
        bytes: UnsafeRawBufferPointer,
        intersectingSpans: [(start: UInt64, end: UInt64, length: UInt64, kind: DataInCodeSpan.Kind)],
        features: Features,
        into records: inout [InstructionRecord],
        sink: inout OperandSink,
    ) {
        var spanCursor = 0
        for wordIndex in 0 ..< wordCount {
            let byteOffset = wordIndex &* 4
            let wordStart = UInt64(byteOffset)
            let wordEnd = wordStart &+ 4
            let address = baseAddress &+ wordStart

            while spanCursor < intersectingSpans.count,
                  intersectingSpans[spanCursor].end <= wordStart
            {
                spanCursor &+= 1
            }

            let intersects = spanCursor < intersectingSpans.count
                && intersectingSpans[spanCursor].start < wordEnd
                && wordStart < intersectingSpans[spanCursor].end

            let encoding = UInt32(bytes[byteOffset])
                | (UInt32(bytes[byteOffset &+ 1]) << 8)
                | (UInt32(bytes[byteOffset &+ 2]) << 16)
                | (UInt32(bytes[byteOffset &+ 3]) << 24)
            let operandStart = UInt32(truncatingIfNeeded: sink.mark)
            let draft: DecodedDraft = intersects
                ? .dataMarker(at: address, encoding: encoding)
                : MachineCodeDecoder.dispatch(
                    encoding: encoding,
                    address: address,
                    families: .standard,
                    features: features,
                    &sink,
                )

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
                operandCount: draft.operandCount,
                scalableReads: draft.scalableReads,
                scalableWrites: draft.scalableWrites,
                scalableEffect: draft.scalableEffect,
            ))
        }
    }

    /// Read the 1, 2, or 3 residual bytes and append a truncated-tail record
    /// (residual packed into `encoding` at the low bits, high bits zero,
    /// operands empty, `operandCount` carrying the residual byte count).
    private static func appendTruncatedTail(
        residual: Int,
        tailOffset: Int,
        tailAddress: UInt64,
        bytes: UnsafeRawBufferPointer,
        operandsCount: Int,
        into records: inout [InstructionRecord],
    ) {
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

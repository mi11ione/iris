// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

public extension InstructionStream {
    /// Retain-free scoped access: pins the buffers for the duration of `body`,
    /// yielding ``BorrowedInstruction`` views. Use it for hot loops that touch
    /// operands; use ``Instruction`` everywhere else.
    ///
    /// Everything derived from the session dangles once `body` returns — copy
    /// out instead. Results are identical to the ``Instruction`` path.
    @inlinable
    func withSession<R>(_ body: (Session) -> R) -> R {
        records.withUnsafeBufferPointer { pinnedRecords in
            operands.withUnsafeBufferPointer { pinnedOperands in
                body(Session(
                    baseAddress: baseAddress,
                    byteCount: byteCount,
                    records: pinnedRecords,
                    operands: pinnedOperands,
                ))
            }
        }
    }

    /// Pinned-buffer access scope over one ``InstructionStream``, created only
    /// by ``InstructionStream/withSession(_:)``.
    @frozen
    struct Session: RandomAccessCollection {
        public typealias Element = BorrowedInstruction
        public typealias Index = Int

        /// VM base address of the buffer the stream was decoded from
        /// (the lookup arithmetic's origin).
        public let baseAddress: UInt64
        /// Byte length of the buffer the stream was decoded from
        /// (the lookup arithmetic's bound).
        public let byteCount: UInt64
        /// The pinned record storage — ``InstructionStream/records``
        /// without array overhead. Valid only within the session scope.
        public let records: UnsafeBufferPointer<InstructionRecord>
        /// The pinned operand side buffer —
        /// ``InstructionStream/operands`` without array overhead.
        /// Valid only within the session scope.
        public let operands: UnsafeBufferPointer<Operand>

        @usableFromInline
        init(
            baseAddress: UInt64,
            byteCount: UInt64,
            records: UnsafeBufferPointer<InstructionRecord>,
            operands: UnsafeBufferPointer<Operand>,
        ) {
            self.baseAddress = baseAddress
            self.byteCount = byteCount
            self.records = records
            self.operands = operands
        }

        /// Always 0.
        @inlinable public var startIndex: Int {
            0
        }

        /// One past the last record; `count == records.count`.
        @inlinable public var endIndex: Int {
            records.count
        }

        /// The borrowed instruction at element index `position` (not an
        /// address — address lookup is the labeled
        /// ``subscript(address:)``); traps when out of range (standard
        /// library collection semantics).
        @inlinable
        public subscript(position: Int) -> BorrowedInstruction {
            precondition(position >= 0 && position < records.count)
            let record = records[position]
            return BorrowedInstruction(record: record, operands: operands(for: record))
        }

        /// Iteration state: a position over the pinned record buffer.
        /// Element formation is identical to the session subscript's,
        /// with the iterator's own bound check standing in for the
        /// subscript precondition.
        @frozen
        public struct Iterator: IteratorProtocol {
            @usableFromInline
            let session: Session
            @usableFromInline
            var position: Int

            @usableFromInline
            init(session: Session) {
                self.session = session
                position = 0
            }

            /// The next borrowed instruction, or `nil` past the end.
            @inlinable
            public mutating func next() -> BorrowedInstruction? {
                guard position < session.records.count else { return nil }
                let record = session.records[position]
                position &+= 1
                return BorrowedInstruction(record: record, operands: session.operands(for: record))
            }
        }

        /// A retain-free iterator over the session's elements.
        @inlinable
        public func makeIterator() -> Iterator {
            Iterator(session: self)
        }

        /// Constant-time address lookup, retain-free. Same contract as
        /// ``InstructionStream/instruction(at:)``: `address` must be the
        /// start address of a record (modular delta a multiple of 4, or
        /// the truncated-tail record's address); unaligned addresses and
        /// addresses outside the stream return `nil`.
        @inlinable
        @inline(__always)
        public func instruction(at address: UInt64) -> BorrowedInstruction? {
            let delta = address &- baseAddress
            guard delta < byteCount else { return nil }
            guard delta % 4 == 0 else { return nil }
            let index = Int(delta / 4)
            guard index < records.count else { return nil }
            let record = records[index]
            return BorrowedInstruction(record: record, operands: operands(for: record))
        }

        /// Containing-lookup, retain-free. Same contract as
        /// ``InstructionStream/instruction(containing:)``: accepts
        /// unaligned addresses, rounding down to the containing word.
        @inlinable
        @inline(__always)
        public func instruction(containing address: UInt64) -> BorrowedInstruction? {
            let delta = address &- baseAddress
            guard delta < byteCount else { return nil }
            let index = Int(delta / 4)
            guard index < records.count else { return nil }
            let record = records[index]
            return BorrowedInstruction(record: record, operands: operands(for: record))
        }

        /// Subscript form of ``instruction(at:)``. Labeled, so an
        /// address literal can never silently resolve against the
        /// collection's element-index subscript.
        @inlinable
        @inline(__always)
        public subscript(address address: UInt64) -> BorrowedInstruction? {
            instruction(at: address)
        }

        /// The borrowed operand slice for a record — the retain-free mirror of
        /// ``InstructionStream/operands(for:)``, with the same contract:
        /// truncated-tail records and hostile hand-built indices form empty.
        /// `lo <= hi` always holds, so one upper-bound comparison is the whole
        /// clamp.
        @inlinable
        @inline(__always)
        public func operands(for record: InstructionRecord) -> UnsafeBufferPointer<Operand> {
            let lo = Int(record.operandStart)
            let hi = lo &+ Int(record.operandCount)
            if record.category != .truncatedTail, hi <= operands.count {
                return UnsafeBufferPointer(rebasing: operands[lo ..< hi])
            }
            return UnsafeBufferPointer(rebasing: operands[0 ..< 0])
        }
    }
}

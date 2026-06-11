// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The closure-scoped session tier: pin the stream's record and operand
// arrays once, then look up and iterate BorrowedInstruction views with
// zero per-element reference counting. Exactly the shape the
// borrowing-view experiment measured
// (Benchmarks/Sources/iris-bench/ViewExperiment.swift); the
// first-class ~Escapable view is the post-1.0 successor once lifetime
// dependencies land non-experimental.

public extension InstructionStream {
    /// Scoped, retain-free access to the packed storage: pins the
    /// stream's record and operand buffers for the duration of `body`
    /// and passes it a ``Session`` whose lookups and iteration produce
    /// ``BorrowedInstruction`` views with no per-element reference
    /// counting and no allocation.
    ///
    /// **When to use which tier.** The ergonomic ``Instruction`` path
    /// (collection iteration, ``instruction(at:)``) is the default:
    /// forming each view retains the operand buffer, and whether the
    /// optimizer elides that retain/release pair depends on the
    /// surrounding code — the same lookup loop can pay several times
    /// the session's cost in one context and near-parity in another,
    /// and the caller cannot control which. Inside a session the cost
    /// is stable regardless of that context: lookups run at a small
    /// constant factor above raw ``records`` index arithmetic, and a
    /// full-operand walk runs at parity with a raw record walk. Use a
    /// session for hot loops that touch operands; use ``Instruction``
    /// views everywhere else. Measured figures with hardware context
    /// live in the repository's benchmark record
    /// (`Benchmarks/README.md`); the stability and the ratios
    /// are the contract, not any absolute number.
    ///
    /// **Escape safety.** The session and every value derived from it —
    /// each ``BorrowedInstruction``, its `operands` slice, and the
    /// session's pinned ``Session/records``/``Session/operands`` buffers
    /// — are valid only until `body` returns. `body` must not store
    /// them, return them as (or inside) its result, or capture them in
    /// an escaping closure or task: the pointers dangle once the scope
    /// exits. Copy data out instead — ``BorrowedInstruction/record`` is
    /// an independent value, and `Array(view.operands)` materializes
    /// operands. The session is not `Sendable`, so the compiler rejects
    /// sending it across concurrency domains.
    ///
    /// Session results are identical to view results: for every index
    /// and address, the session yields the same record and the same
    /// operand sequence as the ``Instruction`` path over the same
    /// stream (pinned by golden equality tests across both paths).
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

    /// Pinned-buffer access scope over one ``InstructionStream``,
    /// created by ``InstructionStream/withSession(_:)`` — the only
    /// producer, so a session always wraps genuinely pinned storage.
    ///
    /// A session is a `RandomAccessCollection` of ``BorrowedInstruction``
    /// elements, one per record (the truncated-tail record is an
    /// ordinary element with an empty operand slice), and mirrors the
    /// stream's address lookups: ``instruction(at:)``,
    /// ``instruction(containing:)``, and the labeled
    /// ``subscript(address:)``, all constant-time modular arithmetic
    /// with the same nil conditions as their ``InstructionStream``
    /// counterparts. Element formation performs no reference counting —
    /// the performance and escape-safety contract is documented on
    /// ``InstructionStream/withSession(_:)``.
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

        /// The borrowed operand slice for a record — the retain-free
        /// mirror of ``InstructionStream/operands(for:)`` with the same
        /// contract: truncated-tail records form empty explicitly (their
        /// `operandCount` carries the residual byte count, never an
        /// operand range), and hostile hand-built indices clamp to
        /// empty. `lo <= hi` always holds (`hi` is `lo` plus an 8-bit
        /// count, no overflow), so one upper-bound comparison is the
        /// complete clamp.
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

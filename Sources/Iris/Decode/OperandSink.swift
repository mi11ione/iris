// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The flat operand buffer for one stream, written by the family decoders.
struct OperandSink {
    private var storage: [Operand]

    init() {
        storage = []
    }

    /// Reserve for a whole buffer up front, so the per-word appends never
    /// grow.
    init(reservingCapacity capacity: Int) {
        storage = []
        storage.reserveCapacity(capacity)
    }

    /// Everything emitted so far, in emission order.
    var operands: [Operand] {
        storage
    }

    /// The index the next emitted operand will occupy.
    @inline(__always)
    var mark: Int {
        storage.count
    }

    /// The operands emitted since `mark`, as a count that fits a draft.
    @inline(__always)
    func count(since mark: Int) -> UInt8 {
        UInt8(truncatingIfNeeded: storage.count &- mark)
    }

    /// Append one operand without reporting a count.
    @inline(__always)
    mutating func append(_ operand: Operand) {
        reserveFirstBlock()
        storage.append(operand)
    }

    /// Size the first allocation to the widest operand list any decoder emits,
    /// lazily, so a word emitting nothing allocates nothing.
    @inline(__always)
    private mutating func reserveFirstBlock() {
        if storage.capacity == 0 { storage.reserveCapacity(8) }
    }
}

extension OperandSink {
    @inline(__always)
    mutating func emit(_ a0: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        return 1
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        return 2
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand, _ a2: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        return 3
    }

    @inline(__always)
    mutating func emit(_ a0: Operand, _ a1: Operand, _ a2: Operand, _ a3: Operand) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        storage.append(a3)
        return 4
    }

    @inline(__always)
    mutating func emit(
        _ a0: Operand, _ a1: Operand, _ a2: Operand, _ a3: Operand, _ a4: Operand,
    ) -> UInt8 {
        reserveFirstBlock()
        storage.append(a0)
        storage.append(a1)
        storage.append(a2)
        storage.append(a3)
        storage.append(a4)
        return 5
    }
}

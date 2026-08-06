// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A decoded ARM64 instruction: the ergonomic tier over the packed
/// ``InstructionRecord``, with zero-based ``operands`` and canonical ``text``.
///
/// Equality compares semantic fields and operand contents, not side-buffer
/// indices. See <doc:TheSemanticLayer>.
@frozen
public struct Instruction: Sendable, Hashable, CustomStringConvertible {
    /// The packed record this view presents.
    public let record: InstructionRecord
    /// This instruction's operands, zero-based.
    public let operands: Operands

    @usableFromInline
    init(record: InstructionRecord, operands: Operands) {
        self.record = record
        self.operands = operands
    }

    /// Build a standalone instruction owning its operand buffer.
    ///
    /// Truncated-tail records carry no operands by contract, so the view
    /// forms empty for them regardless of `operands`.
    public init(
        address: UInt64 = 0,
        encoding: UInt32 = 0,
        mnemonic: Mnemonic,
        semanticReads: RegisterSet = .empty,
        semanticWrites: RegisterSet = .empty,
        branchClass: BranchClass = .none,
        memoryAccess: MemoryAccess = .none,
        memoryOrdering: MemoryOrdering = [],
        flagEffect: FlagEffect = .none,
        category: Category,
        operands: [Operand] = [],
        scalableReads: ScalableRegisterSet = .empty,
        scalableWrites: ScalableRegisterSet = .empty,
        scalableEffect: ScalableEffect = .none,
    ) {
        record = InstructionRecord(
            address: address,
            semanticReads: semanticReads,
            semanticWrites: semanticWrites,
            encoding: encoding,
            operandStart: 0,
            mnemonic: mnemonic,
            branchClass: branchClass,
            memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering,
            flagEffect: flagEffect,
            category: category,
            operandCount: UInt8(truncatingIfNeeded: operands.count),
            scalableReads: scalableReads,
            scalableWrites: scalableWrites,
            scalableEffect: scalableEffect,
        )
        self.operands = category == .truncatedTail
            ? Operands(base: [], offset: 0, count: 0)
            : Operands(base: operands, offset: 0, count: operands.count)
    }

    /// Source VM address of the instruction word (modulo 2^64, see
    /// ``InstructionStream``'s address model).
    @inlinable public var address: UInt64 {
        record.address
    }

    /// Raw 4-byte instruction encoding (truncated-tail records pack their
    /// residual bytes at the low bits).
    @inlinable public var encoding: UInt32 {
        record.encoding
    }

    /// Canonical preferred-alias-resolved mnemonic.
    @inlinable public var mnemonic: Mnemonic {
        record.mnemonic
    }

    /// Bitmask of registers semantically read by this instruction.
    @inlinable public var semanticReads: RegisterSet {
        record.semanticReads
    }

    /// Bitmask of registers semantically written by this instruction.
    @inlinable public var semanticWrites: RegisterSet {
        record.semanticWrites
    }

    /// Scalable (SVE/SME) state semantically read.
    @inlinable public var scalableReads: ScalableRegisterSet {
        record.scalableReads
    }

    /// Scalable (SVE/SME) state semantically written.
    @inlinable public var scalableWrites: ScalableRegisterSet {
        record.scalableWrites
    }

    /// Control-flow classification.
    @inlinable public var branchClass: BranchClass {
        record.branchClass
    }

    /// Memory-effect classification.
    @inlinable public var memoryAccess: MemoryAccess {
        record.memoryAccess
    }

    /// Memory-ordering bits (acquire / release).
    @inlinable public var memoryOrdering: MemoryOrdering {
        record.memoryOrdering
    }

    /// PSTATE.NZCV write effect.
    @inlinable public var flagEffect: FlagEffect {
        record.flagEffect
    }

    /// Per-instruction scalable/streaming effect flags (partial-write,
    /// streaming-mode relationship, fault behavior).
    @inlinable public var scalableEffect: ScalableEffect {
        record.scalableEffect
    }

    /// Encoding-family attribution / provenance witness.
    @inlinable public var category: Category {
        record.category
    }

    /// Canonical llvm-mc-convention assembly text. Total: every record
    /// renders, undefined and data-marker records render as
    /// `.long 0x<hex>` (raw word, lowercase, unpadded), truncated-tail
    /// records as `.byte 0x.., …` over their residual bytes. Allocates
    /// (returns a `String`).
    public var text: String {
        DisassemblyText.render(self)
    }

    /// Same as ``text``.
    @inlinable public var description: String {
        text
    }

    public static func == (lhs: Instruction, rhs: Instruction) -> Bool {
        lhs.record.address == rhs.record.address
            && lhs.record.encoding == rhs.record.encoding
            && lhs.record.mnemonic == rhs.record.mnemonic
            && lhs.record.semanticReads == rhs.record.semanticReads
            && lhs.record.semanticWrites == rhs.record.semanticWrites
            && lhs.record.scalableReads == rhs.record.scalableReads
            && lhs.record.scalableWrites == rhs.record.scalableWrites
            && lhs.record.branchClass == rhs.record.branchClass
            && lhs.record.memoryAccess == rhs.record.memoryAccess
            && lhs.record.memoryOrdering == rhs.record.memoryOrdering
            && lhs.record.flagEffect == rhs.record.flagEffect
            && lhs.record.scalableEffect == rhs.record.scalableEffect
            && lhs.record.category == rhs.record.category
            && lhs.record.tailByteCount == rhs.record.tailByteCount
            && lhs.operands == rhs.operands
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(record.address)
        hasher.combine(record.encoding)
        hasher.combine(record.mnemonic)
        hasher.combine(record.semanticReads)
        hasher.combine(record.semanticWrites)
        hasher.combine(record.scalableReads)
        hasher.combine(record.scalableWrites)
        hasher.combine(record.branchClass)
        hasher.combine(record.memoryAccess)
        hasher.combine(record.memoryOrdering)
        hasher.combine(record.flagEffect)
        hasher.combine(record.scalableEffect)
        hasher.combine(record.category)
        hasher.combine(record.tailByteCount)
        operands.hash(into: &hasher)
    }
}

public extension Instruction {
    /// A zero-based view of one instruction's operands, so `ops[0]` is the first
    /// wherever it sits in the shared buffer. Equality is element-wise over the
    /// window, so equal lists from different streams compare equal.
    @frozen
    struct Operands: RandomAccessCollection, Sendable, Hashable {
        public typealias Element = Operand
        public typealias Index = Int

        @usableFromInline let base: [Operand]
        @usableFromInline let offset: Int
        /// Number of operands in the view.
        public let count: Int

        @usableFromInline
        init(base: [Operand], offset: Int, count: Int) {
            self.base = base
            self.offset = offset
            self.count = count
        }

        /// Always 0, the view is zero-based.
        @inlinable public var startIndex: Int {
            0
        }

        /// One past the last operand; equals ``count``.
        @inlinable public var endIndex: Int {
            count
        }

        /// The operand at zero-based `position`; traps when out of
        /// range (standard library collection semantics).
        @inlinable
        public subscript(position: Int) -> Operand {
            precondition(position >= 0 && position < count)
            return base[offset &+ position]
        }

        public static func == (lhs: Operands, rhs: Operands) -> Bool {
            guard lhs.count == rhs.count else { return false }
            for i in 0 ..< lhs.count
                where lhs.base[lhs.offset &+ i] != rhs.base[rhs.offset &+ i]
            {
                return false
            }
            return true
        }

        public func hash(into hasher: inout Hasher) {
            hasher.combine(count)
            for i in 0 ..< count {
                hasher.combine(base[offset &+ i])
            }
        }
    }
}

extension Instruction.Operands: ExpressibleByArrayLiteral {
    /// Build a standalone operand view from a literal list — the seam for a
    /// caller that has operands and needs the view type (validation helpers,
    /// synthetic records, fixtures). The literal owns its storage, so it costs
    /// one allocation; decode emits into the stream's buffer instead.
    public init(arrayLiteral elements: Operand...) {
        self.init(base: elements, offset: 0, count: elements.count)
    }
}

public extension Instruction {
    /// True when this record is the decoder's UNDEFINED witness. The raw word is
    /// preserved in ``encoding``. Claims only that Iris decodes nothing there,
    /// not that the bytes are meaningless to other tooling.
    @inlinable
    var isUndefined: Bool {
        record.projectedIsUndefined
    }
}

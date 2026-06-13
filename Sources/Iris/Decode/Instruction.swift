// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Instruction. The ergonomic per-instruction value: a copied 40-byte
// record plus a zero-based operand view over the stream's side buffer.
// Forming one from a stream is a register-sized copy plus one retain ,
// zero heap allocation; standalone values (tier-0 decode, synthetic
// instructions, test fixtures) own a private operand buffer through the
// same type, so there is no stream-backed vs standalone mode split.

/// A decoded ARM64 instruction.
///
/// `Instruction` is the ergonomic tier over the packed storage: direct
/// field access (`address`, `mnemonic`, `semanticReads`, …), zero-based
/// ``operands``, canonical ``text``, and the semantic conveniences
/// layered on top. It is produced by iterating an ``InstructionStream``,
/// by the stream's address lookups, or standalone by the tier-0
/// ``decode(_:at:features:)`` function and the materializing initializer.
///
/// Forming an `Instruction` from a stream copies the 40-byte record and
/// wraps the stream's operand buffer in a view, one retain, zero heap
/// allocation. Only ``text`` (returns a `String`) and the materializing
/// initializer (owns a fresh operand array) allocate.
///
/// **Equality is semantic.** Two `Instruction` values compare equal when
/// their semantic record fields and operand *contents* match, the
/// record's `operandStart`/`operandCount` side-buffer indices are
/// excluded, so semantically identical instructions from different
/// streams compare equal. (On truncated-tail records the residual byte
/// count, which `operandCount` carries, *does* participate.) This is
/// deliberately different from ``InstructionRecord``, whose synthesized
/// equality includes the side-buffer indices, index equality is the
/// correct meaning for raw storage.
///
/// The semantic predicates and properties layered on top (``isCall``,
/// ``isReturn``, ``readsMemory``, ``writesMemory``,
/// ``usesPointerAuthentication``, ``branchTarget``, ``pcRelativeTarget``,
/// and the register / flag accessors) are grouped on this page under
/// Topics, and <doc:TheSemanticLayer> walks them with examples.
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

    /// Materializing initializer for standalone values (tier-0 results,
    /// synthetic instructions, test fixtures). Wraps `operands` in a
    /// self-owned buffer.
    ///
    /// The packed record is assembled with `operandStart` 0 and
    /// `operandCount` derived from `operands.count`. Truncated-tail
    /// instructions (`category == .truncatedTail`) have no operands by
    /// contract, so the operand view forms empty for them regardless of
    /// `operands`; decode never materializes a tail this way (tails are
    /// produced by buffer-level decode, where `operandCount` carries the
    /// residual byte count, see ``InstructionRecord/tailByteCount``).
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
        )
        // Explicit truncated-tail branch: tail records carry no operands
        // (their operandCount is the residual byte count), so the view
        // forms empty rather than presenting caller-supplied elements.
        self.operands = category == .truncatedTail
            ? Operands(base: [], offset: 0, count: 0)
            : Operands(base: operands, offset: 0, count: operands.count)
    }

    // Projections, direct loads from the copied record, allocation-free.

    /// Source VM address of the instruction word (modulo 2^64, see
    /// ``InstructionStream``'s address model).
    @inlinable public var address: UInt64 {
        record.address
    }

    /// Raw 4-byte instruction encoding (truncated-tail records pack
    /// their residual bytes at the low bits).
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

    // Custom semantic equality/hashing, see the type documentation.
    // Synthesized conformance is deliberately not used: it would compare
    // `operandStart` (a side-buffer index that differs across streams
    // for semantically identical instructions) and the operand views'
    // backing arrays.

    public static func == (lhs: Instruction, rhs: Instruction) -> Bool {
        lhs.record.address == rhs.record.address
            && lhs.record.encoding == rhs.record.encoding
            && lhs.record.mnemonic == rhs.record.mnemonic
            && lhs.record.semanticReads == rhs.record.semanticReads
            && lhs.record.semanticWrites == rhs.record.semanticWrites
            && lhs.record.branchClass == rhs.record.branchClass
            && lhs.record.memoryAccess == rhs.record.memoryAccess
            && lhs.record.memoryOrdering == rhs.record.memoryOrdering
            && lhs.record.flagEffect == rhs.record.flagEffect
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
        hasher.combine(record.branchClass)
        hasher.combine(record.memoryAccess)
        hasher.combine(record.memoryOrdering)
        hasher.combine(record.flagEffect)
        hasher.combine(record.category)
        hasher.combine(record.tailByteCount)
        operands.hash(into: &hasher)
    }
}

public extension Instruction {
    /// A zero-based random-access view of one instruction's operands.
    ///
    /// `Operands` replaces raw side-buffer index arithmetic: `ops[0]` is
    /// always the instruction's first operand regardless of where the
    /// operands sit in the stream's shared buffer. Stream-formed views
    /// reference the stream's buffer (no copy); standalone instructions
    /// own their buffer through the same type.
    ///
    /// Equality and hashing are element-wise over the window's contents
    /// only (synthesized conformance would compare the entire backing
    /// arrays), so equal operand lists from different streams compare
    /// equal, value semantics.
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

public extension Instruction {
    /// True when this record is the decoder's UNDEFINED witness, a
    /// reserved or unallocated encoding, or an encoding belonging to an
    /// extension absent from the decode ``Features``. The raw word is
    /// preserved in ``encoding``.
    ///
    /// Does NOT claim the bytes are meaningless to other tooling, only
    /// that Iris decodes nothing there.
    @inlinable
    var isUndefined: Bool {
        record.projectedIsUndefined
    }
}

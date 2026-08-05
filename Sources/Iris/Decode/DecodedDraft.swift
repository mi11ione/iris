// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// DecodedDraft. Mutable work-in-progress type the dispatcher passes to
// family decoders. The stream commits a draft into an `InstructionRecord`
// by pairing it with the operand range the decode emitted; tier-0 `decode`
// materializes a draft into a standalone `Instruction`. Operands do not
// live on the draft: the family decoders emit them straight into the
// stream's `OperandSink` and the draft carries only the count.

/// Mutable per-word decode result, used by the dispatcher and family
/// decoders before commit into the stream's record buffer.
///
/// A `DecodedDraft` holds the same semantic content as an
/// ``InstructionRecord``, minus the operands themselves: those are emitted
/// into the stream's ``OperandSink`` and the draft records only how many.
/// Family decoders construct drafts; the stream commits them. Every field
/// is an integer or a raw-valued enum, so copying a draft through the
/// decode return chain is a memcpy with no outlined copy or destroy —
/// which is what carrying an operand collection here cost.
struct DecodedDraft: Sendable, Equatable {
    var address: UInt64
    var encoding: UInt32
    var mnemonic: Mnemonic
    var semanticReads: RegisterSet
    var semanticWrites: RegisterSet
    var scalableReads: ScalableRegisterSet
    var scalableWrites: ScalableRegisterSet
    var branchClass: BranchClass
    var memoryAccess: MemoryAccess
    var memoryOrdering: MemoryOrdering
    var flagEffect: FlagEffect
    var scalableEffect: ScalableEffect
    var category: Category
    /// Number of operands this draft emitted into the stream's
    /// ``OperandSink``. The operands themselves live in the sink; their
    /// start is the sink's length before this word was dispatched, so the
    /// draft carries no index.
    var operandCount: UInt8

    init(
        address: UInt64,
        encoding: UInt32,
        mnemonic: Mnemonic,
        semanticReads: RegisterSet = .empty,
        semanticWrites: RegisterSet = .empty,
        branchClass: BranchClass = .none,
        memoryAccess: MemoryAccess = .none,
        memoryOrdering: MemoryOrdering = [],
        flagEffect: FlagEffect = .none,
        category: Category,
        operandCount: UInt8 = 0,
        scalableReads: ScalableRegisterSet = .empty,
        scalableWrites: ScalableRegisterSet = .empty,
        scalableEffect: ScalableEffect = .none,
    ) {
        self.address = address
        self.encoding = encoding
        self.mnemonic = mnemonic
        self.semanticReads = semanticReads
        self.semanticWrites = semanticWrites
        self.scalableReads = scalableReads
        self.scalableWrites = scalableWrites
        self.branchClass = branchClass
        self.memoryAccess = memoryAccess
        self.memoryOrdering = memoryOrdering
        self.flagEffect = flagEffect
        self.scalableEffect = scalableEffect
        self.category = category
        self.operandCount = operandCount
    }

    /// Construct the UNDEFINED draft for an encoding the
    /// dispatcher could not route to a family decoder.
    static func undefined(at address: UInt64, encoding: UInt32) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .undefined,
            category: .undefined,
        )
    }

    /// Construct the `UDF` (Permanently Undefined) draft — the
    /// one allocated encoding in the `op0=0` reserved tier
    /// (`bits[31:16] == 0`, `imm16` = bits[15:0]). Exception-generating, no
    /// register effects. Owned by the decoder core, not a family decoder.
    static func udf(
        at address: UInt64,
        encoding: UInt32,
        _ sink: inout OperandSink,
    ) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .udf,
            branchClass: .exception,
            category: .branchesExceptionSystem,
            operandCount: sink.emit(
                .unsignedImmediate(value: UInt64(encoding & 0xFFFF), width: 16),
            ),
        )
    }

    /// Construct the data-in-code marker draft for a word
    /// that intersects a caller-provided data-in-code span.
    static func dataMarker(at address: UInt64, encoding: UInt32) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .dataMarker,
            category: .dataInCodeMarker,
        )
    }

    /// Construct the truncated-tail draft for the residual
    /// 1, 2, or 3 bytes at the end of a buffer whose size is not a
    /// multiple of 4. The residual bytes pack into
    /// ``encoding`` at the low bits in little-endian order; high bits
    /// are zero — a record-contract invariant validation tooling pins.
    static func truncatedTail(at address: UInt64, residualBytes: ArraySlice<UInt8>) -> DecodedDraft {
        var packed: UInt32 = 0
        var shift: UInt32 = 0
        for byte in residualBytes.prefix(3) {
            packed |= UInt32(byte) << shift
            shift &+= 8
        }
        return DecodedDraft(
            address: address,
            encoding: packed,
            mnemonic: .truncatedTail,
            category: .truncatedTail,
        )
    }
}

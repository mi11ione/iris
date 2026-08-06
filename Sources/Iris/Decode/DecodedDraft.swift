// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Mutable per-word decode result, used by the dispatcher and family decoders
/// before commit into the stream's record buffer.
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
    /// ``OperandSink``.
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

    /// Construct the UNDEFINED draft for an encoding the dispatcher could not
    /// route to a family decoder.
    static func undefined(at address: UInt64, encoding: UInt32) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .undefined,
            category: .undefined,
        )
    }

    /// Construct the `UDF` (Permanently Undefined) draft.
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

    /// Construct the data-in-code marker draft for a word that intersects a
    /// caller-provided data-in-code span.
    static func dataMarker(at address: UInt64, encoding: UInt32) -> DecodedDraft {
        DecodedDraft(
            address: address,
            encoding: encoding,
            mnemonic: .dataMarker,
            category: .dataInCodeMarker,
        )
    }

    /// Construct the truncated-tail draft for the residual 1, 2, or 3 bytes at
    /// the end of a buffer whose size is not a multiple of 4.
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

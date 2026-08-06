// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Decode one 4-byte instruction word.
///
/// Total: every word yields a well-formed ``Instruction``; unknown encodings
/// set ``Instruction/isUndefined`` and preserve the raw word. `address` forms
/// PC-relative operands, modulo 2^64. For buffers use ``InstructionStream``.
public func decode(
    _ word: UInt32,
    at address: UInt64 = 0,
    features: Features = [],
) -> Instruction {
    var sink = OperandSink()
    let draft = MachineCodeDecoder.dispatch(
        encoding: word,
        address: address,
        families: .standard,
        features: features,
        &sink,
    )
    return Instruction(
        address: draft.address,
        encoding: draft.encoding,
        mnemonic: draft.mnemonic,
        semanticReads: draft.semanticReads,
        semanticWrites: draft.semanticWrites,
        branchClass: draft.branchClass,
        memoryAccess: draft.memoryAccess,
        memoryOrdering: draft.memoryOrdering,
        flagEffect: draft.flagEffect,
        category: draft.category,
        operands: sink.operands,
        scalableReads: draft.scalableReads,
        scalableWrites: draft.scalableWrites,
        scalableEffect: draft.scalableEffect,
    )
}

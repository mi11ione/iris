// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Tier-0 entry: single-word decode. Three lines in a Playground:
//
//     import Iris
//     let instruction = decode(0xD503201F)
//     print(instruction.text)            // "nop"

/// Decode one 4-byte instruction word.
///
/// Total: every word produces a well-formed ``Instruction`` — unknown or
/// unallocated encodings (and encodings of extensions absent from
/// `features`) produce an `Instruction` whose ``Instruction/isUndefined``
/// is `true` with the raw word preserved, never a plausible-looking
/// wrong answer. The same input always produces the same value.
///
/// `address` participates in PC-relative operand formation (branch
/// labels, ADR/ADRP, literal loads) and is carried on the result;
/// address arithmetic is modulo 2^64. Call as `decode(0xD503201F)` after
/// `import Iris`, or `Iris.decode(0xD503201F)` when a local `decode`
/// shadows the module's.
///
/// This is the word tier; for buffers, use
/// ``InstructionStream/init(bytes:at:features:dataInCode:)-(UnsafeRawBufferPointer,_,_,_)``.
public func decode(
    _ word: UInt32,
    at address: UInt64 = 0,
    features: Features = [],
) -> Instruction {
    let draft = MachineCodeDecoder.dispatch(
        encoding: word,
        address: address,
        families: .standard,
        features: features,
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
        operands: draft.operands,
    )
}

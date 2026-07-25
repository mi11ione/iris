// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Copy `instruction` with selected semantic fields replaced — the
/// mutation vehicle for the checker rejection tests, which feed
/// deliberately-corrupted instructions to the semantic checkers and
/// assert the exact issue discriminator. (Decoded `Instruction` values
/// are immutable; this re-materializes one through the public init.)
func mutated(
    _ instruction: Instruction,
    mnemonic: Mnemonic? = nil,
    semanticReads: RegisterSet? = nil,
    semanticWrites: RegisterSet? = nil,
    branchClass: BranchClass? = nil,
    memoryAccess: MemoryAccess? = nil,
    memoryOrdering: MemoryOrdering? = nil,
    flagEffect: FlagEffect? = nil,
    category: Category? = nil,
    operands: [Operand]? = nil,
    scalableReads: ScalableRegisterSet? = nil,
    scalableWrites: ScalableRegisterSet? = nil,
    scalableEffect: ScalableEffect? = nil,
) -> Instruction {
    Instruction(
        address: instruction.address,
        encoding: instruction.encoding,
        mnemonic: mnemonic ?? instruction.mnemonic,
        semanticReads: semanticReads ?? instruction.semanticReads,
        semanticWrites: semanticWrites ?? instruction.semanticWrites,
        branchClass: branchClass ?? instruction.branchClass,
        memoryAccess: memoryAccess ?? instruction.memoryAccess,
        memoryOrdering: memoryOrdering ?? instruction.memoryOrdering,
        flagEffect: flagEffect ?? instruction.flagEffect,
        category: category ?? instruction.category,
        operands: operands ?? Array(instruction.operands),
        scalableReads: scalableReads ?? instruction.scalableReads,
        scalableWrites: scalableWrites ?? instruction.scalableWrites,
        scalableEffect: scalableEffect ?? instruction.scalableEffect,
    )
}

/// The mutable image of a decoded record. Decoded `Instruction` values are
/// immutable, so the scalable checker-rejection suites edit an image and
/// rebuild through the public init — which lets a perturbation read as an
/// in-place field edit at the call site.
struct InstructionImage {
    var address: UInt64
    var encoding: UInt32
    var mnemonic: Mnemonic
    var semanticReads: RegisterSet
    var semanticWrites: RegisterSet
    var branchClass: BranchClass
    var memoryAccess: MemoryAccess
    var memoryOrdering: MemoryOrdering
    var flagEffect: FlagEffect
    var category: Category
    var operands: [Operand]
    var scalableReads: ScalableRegisterSet
    var scalableWrites: ScalableRegisterSet
    var scalableEffect: ScalableEffect

    init(_ instruction: Instruction) {
        address = instruction.address
        encoding = instruction.encoding
        mnemonic = instruction.mnemonic
        semanticReads = instruction.semanticReads
        semanticWrites = instruction.semanticWrites
        branchClass = instruction.branchClass
        memoryAccess = instruction.memoryAccess
        memoryOrdering = instruction.memoryOrdering
        flagEffect = instruction.flagEffect
        category = instruction.category
        operands = Array(instruction.operands)
        scalableReads = instruction.scalableReads
        scalableWrites = instruction.scalableWrites
        scalableEffect = instruction.scalableEffect
    }

    var rebuilt: Instruction {
        Instruction(
            address: address, encoding: encoding, mnemonic: mnemonic,
            semanticReads: semanticReads, semanticWrites: semanticWrites,
            branchClass: branchClass, memoryAccess: memoryAccess,
            memoryOrdering: memoryOrdering, flagEffect: flagEffect,
            category: category, operands: operands,
            scalableReads: scalableReads, scalableWrites: scalableWrites,
            scalableEffect: scalableEffect,
        )
    }
}

/// `instruction` with `body`'s edits applied — the mutation vehicle for the
/// scalable checker-rejection suites.
func perturbing(_ instruction: Instruction, _ body: (inout InstructionImage) -> Void) -> Instruction {
    var image = InstructionImage(instruction)
    body(&image)
    return image.rebuilt
}

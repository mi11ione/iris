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
    )
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Writeback. Pre- and post-indexed addressing
// modes for load/store instructions update the base register; this
// enum tags which form (or none).

/// Writeback mode of an indexed addressing operand.
///
/// Carried by ``MemoryOperand/writeback`` for the load/store instruction
/// families that update the base register as a side effect.
@frozen
public enum Writeback: UInt8, Sendable, Hashable {
    /// No writeback. Base register is read but not modified.
    case none = 0
    /// Pre-indexed — base = base + offset, then access at the new base
    /// (`[Xn, #imm]!`).
    case preIndex = 1
    /// Post-indexed — access at the current base, then base = base + offset
    /// (`[Xn], #imm`).
    case postIndex = 2
}

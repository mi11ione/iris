// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MemoryOperand + MemoryBase. The addressing-
// mode operand grammar of every ARM64 load and store. `MemoryBase` is
// either a register (the common case) or PC (for `LDR` literal family).
// Displacement is widened to `Int64` so ADRP-class byte offsets (±4 GB)
// fit without overflow; ARM64 load/store instructions commonly use
// 9-bit / 12-bit / 19-bit subsets of this range.

/// Addressing-mode operand for load / store instructions.
///
/// `MemoryOperand` captures the full pre-effective-address operand
/// triple: base register (or PC), optional index register, and signed
/// byte displacement, plus the extend / shift / writeback modifiers that
/// modulate the address calculation. The decoder does *not* compute
/// the effective address — that is left to consumers.
@frozen
public struct MemoryOperand: Sendable, Hashable {
    /// Base register, or PC for `LDR` literal family.
    public let base: MemoryBase
    /// Optional index register (for register-offset addressing modes).
    public let index: RegisterRef?
    /// Signed byte displacement. Pre-scaled (i.e. already × element size
    /// where the instruction's encoding scales it).
    public let displacement: Int64
    /// Extend modifier for an indexed addressing mode; ``ExtendKind/none``
    /// when there is no extend (immediate-offset or simple register
    /// indexing).
    public let extend: ExtendKind
    /// `log2` scale applied to the displacement or index (0..4); zero
    /// when no scale is applied.
    public let shift: UInt8
    /// Writeback mode (none / pre-index / post-index).
    public let writeback: Writeback

    @inlinable
    public init(
        base: MemoryBase,
        index: RegisterRef? = nil,
        displacement: Int64 = 0,
        extend: ExtendKind = .none,
        shift: UInt8 = 0,
        writeback: Writeback = .none,
    ) {
        self.base = base
        self.index = index
        self.displacement = displacement
        self.extend = extend
        self.shift = shift
        self.writeback = writeback
    }
}

/// Base for a ``MemoryOperand`` — a named register, or the program
/// counter (for PC-relative literal loads).
@frozen
public enum MemoryBase: Sendable, Hashable {
    /// Base is a named register (the common case).
    case register(RegisterRef)
    /// Base is the program counter — `LDR (literal)`, `LDRSW (literal)`,
    /// `PRFM (literal)`. The operand's `displacement` is the pre-scaled
    /// PC-relative byte offset to the literal pool target.
    case pc
}

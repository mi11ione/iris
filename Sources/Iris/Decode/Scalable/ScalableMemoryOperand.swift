// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// An SVE memory-addressing operand — contiguous or gather/scatter.
///
/// ``base`` is a GPR or a scalable-vector base; ``index`` is the gather/scatter
/// vector index, nil for contiguous forms; ``mulVL`` marks vector-length-scaled
/// addressing.
@frozen
public struct ScalableMemoryOperand: Sendable, Hashable {
    /// Address base.
    public let base: Base
    /// Vector index `Zm.<S|D>` for gather/scatter; `nil` for contiguous.
    public let index: ScalableVectorRef?
    /// Scalar (GPR) index `Xm` for the register-offset and vector-base
    /// non-temporal forms; `nil` when there is none. Distinct from ``index``,
    /// the `Zm` gather/scatter vector index — an address carries at most one.
    public let scalarIndex: RegisterRef?
    /// Extend applied to the vector index (`uxtw` / `sxtw` / `lsl` / none).
    public let indexExtend: ExtendKind
    /// Log2 scale applied to the index (0..4; SME `LD1Q`/`ST1Q` use 4).
    public let scaleShift: UInt8
    /// Signed immediate displacement — byte offset, or (with ``mulVL``)
    /// vector-length-scaled units. `Int32` is ample for SVE addressing
    /// immediates and keeps ``Operand`` within its size bound.
    public let displacement: Int32
    /// `#imm, mul vl` vector-length-scaled addressing.
    public let mulVL: Bool

    @inlinable
    @inline(__always)
    public init(
        base: Base,
        index: ScalableVectorRef? = nil,
        scalarIndex: RegisterRef? = nil,
        indexExtend: ExtendKind = .none,
        scaleShift: UInt8 = 0,
        displacement: Int32 = 0,
        mulVL: Bool = false,
    ) {
        self.base = base
        self.index = index
        self.scalarIndex = scalarIndex
        self.indexExtend = indexExtend
        self.scaleShift = scaleShift
        self.displacement = displacement
        self.mulVL = mulVL
    }

    /// The base of an SVE address — a GPR or a scalable-vector base.
    @frozen
    public enum Base: Sendable, Hashable {
        /// `[Xn, …]` — a GPR base (`Xn` or `SP`).
        case gpr(RegisterRef)
        /// `[Zn.<T>, …]` — a vector base (SVE vector-plus-immediate gather).
        case vector(ScalableVectorRef)
    }
}

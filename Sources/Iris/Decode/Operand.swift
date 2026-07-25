// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Operand. The single discriminated union over every operand
// variant ARM64 produces. Closed for layout. Cases are added when a
// reality not yet anticipated requires representation; consumers must
// use exhaustive switches and recompile when cases are added (Iris is
// source-distributed, no library-evolution mode in Package.swift).

/// One operand of an ``InstructionRecord``.
///
/// `Operand` is a single discriminated union over every operand variant
/// ARM64 produces — the decoder core's one operand type. Consumers
/// can write a single exhaustive switch over an instruction's operands
/// without per-family dispatch.
@frozen
public enum Operand: Sendable, Hashable {
    /// Named GPR (`Wn`/`Xn`/`SP`/`WSP`/`XZR`/`WZR`) or SIMD register
    /// (`Vn`) — see ``RegisterRef``.
    case register(RegisterRef)

    /// SIMD/FP register with view-shape (`Vn.<arr>` / `Bn..Qn` /
    /// `Vn.<arr>[i]`).
    case vectorRegister(VectorRegisterRef)

    /// Signed integer immediate at the given bit-width.
    case immediate(value: Int64, width: UInt8)

    /// Unsigned integer immediate at the given bit-width.
    case unsignedImmediate(value: UInt64, width: UInt8)

    /// Floating-point immediate — `bits` is the raw IEEE 754 bit-pattern
    /// at the declared width.
    case floatImmediate(bits: UInt64, kind: FloatImmediateKind)

    /// Pre-scaled PC-relative byte offset to a label. Consumers compute
    /// the absolute target as `record.address &+ UInt64(bitPattern: byteOffset)`,
    /// or use the resolved ``Instruction/branchTarget`` /
    /// ``Instruction/pcRelativeTarget``. Int64 width covers ADRP's ±4 GB
    /// byte range. Used by `ADR` and PC-relative branches. For `ADRP`'s
    /// page-relative target, see ``pageLabel(byteOffset:)``.
    case label(byteOffset: Int64)

    /// Load/store addressing-mode operand.
    case memory(MemoryOperand)

    /// Register with shift modifier — `Xn, LSL #amount` and variants.
    case shiftedRegister(reg: RegisterRef, shift: ShiftKind, amount: UInt8)

    /// Register with extend modifier — `Wn, UXTW #shift` and variants.
    case extendedRegister(reg: RegisterRef, extend: ExtendKind, shift: UInt8)

    /// System register encoded as the (op0, op1, CRn, CRm, op2) tuple.
    case systemRegister(SystemRegisterEncoding)

    /// Condition code for a conditional instruction (`B.cond`, `CSEL`,
    /// `CCMP`, etc.).
    case conditionCode(ConditionCode)

    /// PSTATE field for `MSR (immediate)`.
    case pstateField(PSTATEField)

    /// Barrier option for `DSB` / `DMB` / `ISB`.
    case barrierOption(BarrierOption)

    /// Prefetch operation for `PRFM` / `PRFUM`.
    case prefetchOperation(PrefetchOperation)

    /// System-op operand for `IC` / `DC` / `AT` / `TLBI`.
    case systemOp(SystemOp)

    /// AMX coprocessor operand field. Carries the raw 32-bit payload;
    /// opcode-specific interpretation is layered on top.
    case amxField(AMXField)

    /// AMX encoding whose opcode field is outside the documented 0...22
    /// set, or whose operand subfield is outside the documented values
    /// for its opcode (e.g. opcode 17 with operand ≥ 2). Carries the raw
    /// 32-bit encoding so downstream consumers can analyse otherwise-
    /// unrecognised AMX bytes without losing payload.
    case amxUnknown(rawFields: UInt32)

    /// Standalone immediate shift modifier — `LSL #amount` that follows an
    /// immediate operand and has no associated register (cf.
    /// ``shiftedRegister(reg:shift:amount:)``). Used by `ADD/SUB (immediate)`
    /// with `sh=1` (amount=12) and by `MOVN/MOVZ/MOVK` with `hw≠0`
    /// (amount=16/32/48).
    case shiftAmount(kind: ShiftKind, amount: UInt8)

    /// Pre-scaled byte offset to a page-aligned PC-relative target, for
    /// `ADRP`. Consumers compute the absolute page-base target as
    /// `(record.address & ~0xFFF) &+ UInt64(bitPattern: byteOffset)` —
    /// distinct from ``label(byteOffset:)`` whose target is
    /// `record.address &+ byteOffset` — or use the resolved
    /// ``Instruction/pcRelativeTarget``, which performs the page math.
    /// Int64 width covers ADRP's ±4 GB byte range.
    case pageLabel(byteOffset: Int64)

    /// SVE scalable-vector register — `Zn` / `Zn.<T>` / `Zn.<T>[i]`.
    case scalableVector(ScalableVectorRef)

    /// SVE/SME predicate — `Pn` / `Pn.<T>` / `Pn/z` / `Pn/m`, or the
    /// predicate-as-counter `PNn`.
    case scalablePredicate(ScalablePredicateRef)

    /// Multi-vector register group — `{ Zn.<T>, ... }` (consecutive/strided).
    case scalableVectorGroup(ScalableVectorGroup)

    /// Predicate register group — `{ Pn.<T>, Pm.<T> }`.
    case predicateGroup(firstIndex: UInt8, count: UInt8, element: ScalarSize)

    /// SME `ZA` tile — `za` (whole array, `element == nil`) or `zaN.<T>`.
    case zaTile(index: UInt8, element: ScalarSize?)

    /// SME `ZA` tile-slice — `zaN{h|v}.<T>[Wv, #imm]`.
    case zaTileSlice(ZATileSliceOperand)

    /// SME2 `ZA`-array vector — `za.<T>[Wv, #imm{:hi}{, vgx2|vgx4}]`.
    case zaArrayVector(ZAArrayVectorOperand)

    /// SME2 lookup-table register `ZT0`, with an optional index.
    case zt0(elementIndex: UInt8?)

    /// SVE memory addressing — contiguous or gather/scatter.
    case scalableMemory(ScalableMemoryOperand)

    /// SVE predicate-count pattern — `all` / `pow2` / `vlN` / `mulN`.
    case svePredicatePattern(SVEPredicatePattern)

    /// SME2 vector-length multiplier — the trailing `vlx2` / `vlx4` on
    /// predicate-as-counter `WHILE` and `CNTP`. The payload is the
    /// multiplier value (2 or 4).
    case vectorLengthMultiplier(UInt8)
}

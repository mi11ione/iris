// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// FloatImmediateKind. Encodes the width of a
// floating-point immediate carried by `Operand.floatImmediate(bits:kind:)`.

/// Floating-point immediate width.
///
/// `FMOV` and `FCMP` accept FP immediates in three widths corresponding
/// to the source / destination register class.
@frozen
public enum FloatImmediateKind: UInt8, Sendable, Hashable {
    /// Half-precision (IEEE 754 binary16) — `Hn` register class.
    case half = 0
    /// Single-precision (IEEE 754 binary32) — `Sn` register class.
    case single = 1
    /// Double-precision (IEEE 754 binary64) — `Dn` register class.
    case double = 2
}

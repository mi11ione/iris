// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// ConditionCode. The 16 condition codes ARM64
// uses on conditional branches and conditional selects/compares. Raw
// values match the 4-bit `cond` field in the encoding.

/// ARM64 4-bit condition code.
///
/// Carried by ``Operand/conditionCode(_:)``. Values are the canonical
/// encoded condition (e.g. `B.eq` → ``eq``). ``nv`` is the "never"
/// encoding (4-bit value `0b1111`); the architecture treats it as `al`
/// in most contexts but the encoding is distinct.
@frozen
public enum ConditionCode: UInt8, Sendable, Hashable {
    /// Equal (`Z == 1`).
    case eq = 0
    /// Not Equal (`Z == 0`).
    case ne = 1
    /// Carry Set / Unsigned Higher-or-Same (`C == 1`). Also `HS`.
    case cs = 2
    /// Carry Clear / Unsigned Lower (`C == 0`). Also `LO`.
    case cc = 3
    /// Minus / Negative (`N == 1`).
    case mi = 4
    /// Plus / Positive-or-Zero (`N == 0`).
    case pl = 5
    /// Overflow Set (`V == 1`).
    case vs = 6
    /// Overflow Clear (`V == 0`).
    case vc = 7
    /// Unsigned Higher (`C == 1 && Z == 0`).
    case hi = 8
    /// Unsigned Lower-or-Same (`C == 0 || Z == 1`).
    case ls = 9
    /// Signed Greater-or-Equal (`N == V`).
    case ge = 10
    /// Signed Less Than (`N != V`).
    case lt = 11
    /// Signed Greater Than (`Z == 0 && N == V`).
    case gt = 12
    /// Signed Less-or-Equal (`Z == 1 || N != V`).
    case le = 13
    /// Always (unconditional).
    case al = 14
    /// Never — encoded as `0b1111`; behaves like ``al`` but the
    /// encoding is distinct.
    case nv = 15
}

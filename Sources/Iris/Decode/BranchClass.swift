// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Control-flow classification; every record carries exactly one value.
/// Single-valued because the base ISA has no orthogonal combinations, and
/// what an `OptionSet` would add is recoverable from the ``Mnemonic``.
@frozen
public enum BranchClass: UInt8, Sendable, Hashable {
    /// Not a branch. The instruction's execution falls through to the
    /// next word.
    case none = 0

    /// Unconditional direct branch — `B target` family. Target is a
    /// PC-relative immediate encoded in the instruction.
    case direct = 1

    /// Unconditional indirect branch — `BR Xn` family. Target is the
    /// value of a register at execution time.
    case indirect = 2

    /// Conditional branch — `B.cond`, `CBZ`, `CBNZ`, `TBZ`, `TBNZ`.
    /// Direct target encoded as PC-relative immediate; fallthrough is
    /// also a successor.
    case conditional = 3

    /// Function call — `BL` (direct) or `BLR` (indirect). Saves return
    /// address in `X30` (`LR`). Direct vs indirect distinction is
    /// recoverable from the mnemonic.
    case call = 4

    /// Function return — `RET`, `RETAA`, `RETAB`. Indirect through `Xn`
    /// (or implicit `X30`).
    case `return` = 5

    /// Exception-generating — `SVC`, `HVC`, `SMC`, `BRK`, `HLT`, `UDF`,
    /// `DCPS1`/`2`/`3`. Transfers control to a fixed exception vector;
    /// not a normal branch.
    case exception = 6
}

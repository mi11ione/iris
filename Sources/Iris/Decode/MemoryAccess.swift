// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// MemoryAccess. Mutually exclusive by design: `.atomic` means RMW
// (both load and store, with atomic ordering); `.exclusiveLoad` is
// read-only with monitor; `.exclusiveStore` is write-only with monitor.

/// Memory-effect classification of an instruction.
///
/// Every ``InstructionRecord`` carries exactly one of these values.
/// Memory-ordering bits (acquire / release) are tracked separately via
/// ``MemoryOrdering``.
@frozen
public enum MemoryAccess: UInt8, Sendable, Hashable {
    /// Instruction does not access memory.
    case none = 0

    /// Pure read — `LDR`/`LDRB`/`LDRH`/`LDP` and variants.
    case load = 1

    /// Pure write — `STR`/`STRB`/`STRH`/`STP` and variants.
    case store = 2

    /// Read-modify-write atomic — LSE atomics (`LDADD`, `LDSET`, `LDCLR`,
    /// `LDEOR`, `LDSMAX/MIN`, `LDUMAX/MIN`, `SWP`) and `CAS` family.
    /// Both reads and writes memory in one architectural step.
    case atomic = 3

    /// Load-exclusive — `LDXR`/`LDXRB`/`LDXRH`/`LDXP` and acquire
    /// variants. Reads memory and sets the exclusive monitor; pairs with
    /// a later exclusive store.
    case exclusiveLoad = 4

    /// Store-exclusive — `STXR`/`STXRB`/`STXRH`/`STXP` and release
    /// variants. Writes memory if the exclusive monitor is still set.
    case exclusiveStore = 5

    /// Prefetch hint — `PRFM`, `PRFUM`. Architecturally a no-op except
    /// for cache-state effects; classified separately so downstream
    /// dataflow can ignore it without losing the operand information.
    case prefetch = 6
}

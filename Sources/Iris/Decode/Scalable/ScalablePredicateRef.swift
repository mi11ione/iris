// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// scalable-predicate operand reference — Pn / PNn with its qualifier,
// role, counter-view flag, and optional element size / index. The register
// is a bare index 0..15; predicate-as-counter (PN) aliases the same physical
// predicate file, distinguished by `isCounter` (an opcode property).
// Predicates map to ScalableRegisterSet predicate bits, NEVER to RegisterRef
// (a RegisterRef at index n would alias GPR Xn).

/// Reference to an SVE/SME predicate operand — `Pn`, `Pn.<T>`, `Pn/z`,
/// `Pn/m`, or the predicate-as-counter `PNn`.
///
/// Carried by ``Operand/scalablePredicate(_:)``. The register is a bare
/// index (0..15). ``qualifier`` is the `/Z` or `/M` on a governing
/// predicate; ``role`` distinguishes a governing predicate from a result
/// predicate; ``isCounter`` selects the predicate-as-counter (`PN`) view of
/// the same physical register. Its semantic read/write is
/// ``ScalableRegisterSet/insertingPredicate(_:)`` on ``registerIndex``.
@frozen
public struct ScalablePredicateRef: Sendable, Hashable {
    /// Predicate register number 0..15.
    public let registerIndex: UInt8
    /// Element size (`Pn.<T>`); `nil` for a bare `Pn`.
    public let element: ScalarSize?
    /// `/Z`, `/M`, or none.
    public let qualifier: PredicateQualifier
    /// Governing vs result predicate.
    public let role: Role
    /// Predicate-as-counter (`PN`) view of the same physical register.
    public let isCounter: Bool
    /// Immediate index on `PEXT pn8[i]` / `PSEL Pn.<T>[Wv, imm]`; `nil`
    /// otherwise.
    public let elementIndex: UInt8?
    /// Vector-select register on `PSEL Pn.<T>[Wv, imm]` (a semantic GPR
    /// read, W12–W15); `nil` otherwise.
    public let selectRegister: RegisterRef?

    @inlinable
    @inline(__always)
    public init(
        registerIndex: UInt8,
        element: ScalarSize? = nil,
        qualifier: PredicateQualifier = .none,
        role: Role = .governing,
        isCounter: Bool = false,
        elementIndex: UInt8? = nil,
        selectRegister: RegisterRef? = nil,
    ) {
        self.registerIndex = registerIndex & 0b1111 // masked (no trap)
        self.element = element
        self.qualifier = qualifier
        self.role = role
        self.isCounter = isCounter
        self.elementIndex = elementIndex
        self.selectRegister = selectRegister
    }

    /// Whether a predicate is the instruction's governing predicate (its
    /// per-lane enable) or a result predicate (a value it writes).
    @frozen
    public enum Role: UInt8, Sendable, Hashable {
        /// Governing predicate — a per-lane enable read by the instruction.
        case governing = 0
        /// Result predicate — a predicate value the instruction writes.
        case result = 1
    }
}

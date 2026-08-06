// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Reference to a named ARM64 architectural register: a canonical index
/// (0...63 across GPR and SIMD), a ``RegisterRole`` (the one dimension where
/// encoding 31 is ambiguous), and a ``RegisterWidth``. A SIMD register's real
/// width lives on ``VectorRegisterRef``.
@frozen
public struct RegisterRef: Sendable, Hashable {
    /// Canonical register index. 0..30 → X0..X30; 31 → SP/XZR (role
    /// disambiguates); 32..63 → V0..V31.
    public let canonicalIndex: UInt8
    /// Disambiguates the dual-meaning encoding at canonicalIndex 31, and
    /// signals "this is a vector register" for canonicalIndex 32..63.
    public let role: RegisterRole
    /// 32 vs 64 for GPR display; ``RegisterWidth/vectorImplied`` for SIMD.
    public let width: RegisterWidth

    @inlinable
    public init(canonicalIndex: UInt8, role: RegisterRole, width: RegisterWidth) {
        self.canonicalIndex = canonicalIndex
        self.role = role
        self.width = width
    }

    /// `Wn` for n in 0...30. Index 31 is the dual-meaning SP/ZR slot — use
    /// ``wsp()`` or ``wzr()`` there; inputs are masked to 5 bits, so `w(31)`
    /// yields a `.general`-role reference, usually not what a caller wants.
    @inlinable
    public static func w(_ n: UInt8) -> RegisterRef {
        RegisterRef(canonicalIndex: n & 0b11111, role: .general, width: .w32)
    }

    /// `Xn` for n in 0...30. Index 31 is the dual-meaning SP/ZR slot — use
    /// ``sp()`` or ``xzr()`` there; inputs are masked to 5 bits, so `x(31)`
    /// yields a `.general`-role reference, usually not what a caller wants.
    @inlinable
    public static func x(_ n: UInt8) -> RegisterRef {
        RegisterRef(canonicalIndex: n & 0b11111, role: .general, width: .x64)
    }

    /// `WZR` — 32-bit zero register at encoding 31.
    @inlinable
    public static func wzr() -> RegisterRef {
        RegisterRef(canonicalIndex: 31, role: .zeroRegister, width: .w32)
    }

    /// `XZR` — 64-bit zero register at encoding 31.
    @inlinable
    public static func xzr() -> RegisterRef {
        RegisterRef(canonicalIndex: 31, role: .zeroRegister, width: .x64)
    }

    /// `WSP` — 32-bit stack pointer at encoding 31.
    @inlinable
    public static func wsp() -> RegisterRef {
        RegisterRef(canonicalIndex: 31, role: .stackPointer, width: .w32)
    }

    /// `SP` — 64-bit stack pointer at encoding 31.
    @inlinable
    public static func sp() -> RegisterRef {
        RegisterRef(canonicalIndex: 31, role: .stackPointer, width: .x64)
    }

    /// `Vn` for n in 0..31 — SIMD/FP register; width is implied by the
    /// containing ``VectorRegisterRef/view``.
    @inlinable
    public static func simd(_ n: UInt8) -> RegisterRef {
        RegisterRef(canonicalIndex: 32 &+ (n & 0b11111), role: .general, width: .vectorImplied)
    }

    /// True if this reference names a general-purpose register (X0..X30,
    /// W0..W30, SP, WSP, XZR, WZR — anything with canonical-index < 32).
    @inlinable
    @inline(__always)
    public var isGPR: Bool {
        canonicalIndex < 32
    }

    /// True if this reference names a SIMD/FP register (V0..V31 with
    /// canonical-index in 32..63).
    @inlinable
    @inline(__always)
    public var isSIMD: Bool {
        (32 ..< 64).contains(canonicalIndex)
    }

    /// True if this reference is the stack pointer at the architectural
    /// encoding-31 slot (`SP` or `WSP`).
    @inlinable
    @inline(__always)
    public var isStackPointer: Bool {
        role == .stackPointer
    }

    /// True if this reference is the zero register at the architectural
    /// encoding-31 slot (`XZR` or `WZR`).
    @inlinable
    @inline(__always)
    public var isZeroRegister: Bool {
        role == .zeroRegister
    }
}

extension RegisterRef: CustomStringConvertible {
    /// Canonical lowercase register name. Total: a `.general`-role reference at
    /// the encoding-31 slot names the zero register, and hand-built indices at
    /// or past 64 render `"?<index>"`.
    public var name: String {
        switch (canonicalIndex, role, width) {
        case (31, .stackPointer, .x64): return "sp"
        case (31, .stackPointer, .w32): return "wsp"
        case (31, .zeroRegister, .x64): return "xzr"
        case (31, .zeroRegister, .w32): return "wzr"
        case (31, .general, _):
            return width == .x64 ? "xzr" : "wzr"
        default:
            if canonicalIndex < 31 {
                return width == .x64 ? "x\(canonicalIndex)" : "w\(canonicalIndex)"
            }
            if (32 ..< 64).contains(canonicalIndex) {
                return "v\(canonicalIndex &- 32)"
            }
            return "?\(canonicalIndex)"
        }
    }

    /// Same as ``name``.
    @inlinable
    public var description: String {
        name
    }
}

/// Disambiguates the dual-meaning encoding at canonical-index 31, and
/// flags vector-register references.
@frozen
public enum RegisterRole: UInt8, Sendable, Hashable {
    /// Canonical-index 0..30 (X/W register) or 32..63 (SIMD).
    case general = 0
    /// Canonical-index 31, semantic = SP / WSP.
    case stackPointer = 1
    /// Canonical-index 31, semantic = XZR / WZR.
    case zeroRegister = 2
}

/// Display / interpretation width for a GPR; for SIMD use
/// ``vectorImplied`` and let the ``VectorRegisterRef/view`` carry the
/// actual element shape.
@frozen
public enum RegisterWidth: UInt8, Sendable, Hashable {
    /// 32-bit form (Wn, WZR, WSP).
    case w32 = 0
    /// 64-bit form (Xn, XZR, SP).
    case x64 = 1
    /// SIMD/FP register; actual width carried by ``VectorRegisterRef/view``.
    case vectorImplied = 2
}

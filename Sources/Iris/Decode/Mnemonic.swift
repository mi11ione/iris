// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Mnemonic identity. Wrapper-over-UInt16 rather
// than a true Swift `enum` because the ARM64 closed-form mnemonic surface
// is 1,105 declared constants (4 sentinel-range values + 1,101 family
// canonical and alias mnemonics), large enough to make a single
// `enum` declaration tedious and slow to switch over. The wrapper allows
// each family's mnemonic file to add its own `static let` constants in a
// reserved raw-value range.
//
// Raw-value range allocation (any family adding a new constant must use
// a value inside its declared range; tests enforce
// uniqueness and range-membership):
//
//   0     ..< 256   — decoder sentinels (and UDF)
//   256   ..< 1024  — Data Processing — Immediate
//   1024  ..< 2048  — Branches, Exception, System
//   2048  ..< 4096  — Loads & Stores
//   4096  ..< 6144  — Data Processing — Register
//   6144  ..< 12288 — SIMD & Floating-Point
//   12288 ..< 16384 — Crypto + Apple Extensions
//   16384 ..< 65535 — reserved for future extensions
//   65535            — invalid; reserved sentinel for "uninitialized"

/// Closed-form identity for an ARM64 instruction mnemonic.
///
/// `Mnemonic` is a value-typed wrapper over the on-record 16-bit identifier
/// used in ``InstructionRecord``. Decoder sentinels (``undefined``,
/// ``dataMarker``, ``truncatedTail``) are declared here; the encoding
/// families extend the type with their canonical and alias-resolved
/// mnemonics via per-family extensions, each within its allocated
/// raw-value range.
@frozen
public struct Mnemonic: RawRepresentable, Sendable, Hashable {
    /// On-record 16-bit identifier.
    public let rawValue: UInt16

    @inlinable
    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }
}

public extension Mnemonic {
    /// Decoder sentinel — the family-decoder dispatcher had no decoder
    /// registered for this encoding's `op0`, or the encoding fell in a
    /// reserved tier. The record's raw `encoding` is preserved bit-for-bit.
    static let undefined = Mnemonic(rawValue: 0)

    /// Decoder sentinel — the word lies inside (or intersects) a
    /// caller-provided data-in-code span. The bytes are data,
    /// not instructions; the record's `encoding` is the raw 4 bytes.
    static let dataMarker = Mnemonic(rawValue: 1)

    /// Decoder sentinel — the code buffer's size is not a multiple of
    /// 4 bytes; this record represents the residual 1, 2, or 3 bytes at
    /// the buffer's end. The `encoding` field packs the residual bytes
    /// in little-endian at the low bits.
    static let truncatedTail = Mnemonic(rawValue: 2)

    /// `UDF` — Permanently Undefined. The one allocated encoding in the
    /// `op0=0` reserved tier (`0x0000_NNNN`, `imm16` = bits[15:0]). The
    /// decoder core owns it directly — no family decoder claims it — so
    /// it is a sentinel-range mnemonic rather than a BES-range one
    /// despite being exception-generating.
    static let udf = Mnemonic(rawValue: 3)

    /// Reserved raw-value range allocations per declaring file. Each
    /// entry is a `(label, range)` pair where the range is the span of
    /// raw values the declaring family may use for its `static let`
    /// constants. Defined as a single source of truth so any tooling
    /// that wants to render a `Mnemonic` to a human-readable label can
    /// map a raw value back to its declaring family without duplicating
    /// the allocation table.
    /// Mirrors the header-comment table at the top of this file and the
    /// range dispatch inside ``name`` (both pinned together by tests).
    static let allocations: [(label: String, range: ClosedRange<UInt16>)] = [
        ("Sentinels & UDF", 0 ... 255),
        ("Data Processing — Immediate", 256 ... 1023),
        ("Branches, Exception, System", 1024 ... 2047),
        ("Loads & Stores", 2048 ... 4095),
        ("Data Processing — Register", 4096 ... 6143),
        ("SIMD & Floating-Point", 6144 ... 12287),
        ("Crypto + Apple Extensions", 12288 ... 16383),
    ]
}

extension Mnemonic: CustomStringConvertible {
    /// Canonical lowercase name (`"add"`, `"ldp"`, `"b.cond"`).
    ///
    /// Total: decoder sentinels return fixed census labels
    /// (`"undefined"`, `"data"`, `"truncated"`, `"amx-unknown"`; `"udf"`
    /// is a real mnemonic), composite encodings get their manual
    /// spelling lowercased (`"b.cond"`, `"bc.cond"`, `"msr"`), and
    /// unallocated raw values return `"?<raw>"` — deterministic and
    /// debuggable, unreachable via decode. Names are census labels, not
    /// assembly: the assembly rendering of a whole instruction
    /// (including sentinel records) is ``Instruction/text``.
    ///
    /// O(1): a range dispatch (the ``allocations`` table's ranges, made
    /// executable) into a per-family table of static literals declared
    /// beside each family's constants — no allocation on named paths.
    public var name: String {
        switch rawValue {
        case 0 ... 255: Mnemonic.sentinelName(self)
        case 256 ... 1023: Mnemonic.dataProcessingImmediateName(self)
        case 1024 ... 2047: Mnemonic.branchesExceptionSystemName(self)
        case 2048 ... 4095: Mnemonic.loadsAndStoresName(self)
        case 4096 ... 6143: Mnemonic.dataProcessingRegisterName(self)
        case 6144 ... 12287: Mnemonic.simdAndFPName(self)
        case 12288 ... 16383: Mnemonic.cryptoAppleExtensionsName(self)
        default: "?\(rawValue)"
        }
    }

    /// Same as ``name``.
    @inlinable
    public var description: String {
        name
    }

    /// Names for the sentinel range (0...255): the three decoder
    /// sentinels plus UDF, the range's one real mnemonic.
    static func sentinelName(_ m: Mnemonic) -> String {
        switch m {
        case .undefined: "undefined"
        case .dataMarker: "data"
        case .truncatedTail: "truncated"
        case .udf: "udf"
        default: "?\(m.rawValue)"
        }
    }
}

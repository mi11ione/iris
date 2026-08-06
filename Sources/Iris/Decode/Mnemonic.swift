// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Closed-form identity for an ARM64 instruction mnemonic.
///
/// A value-typed wrapper over the on-record 16-bit identifier. The decoder
/// sentinels are declared here; each encoding family extends the type with
/// its own constants inside an allocated raw-value range.
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

    /// Reserved raw-value range allocations per declaring family, as
    /// `(label, range)` pairs. The single source of truth tooling maps a raw
    /// value back through, mirroring the range dispatch inside ``name``.
    static let allocations: [(label: String, range: ClosedRange<UInt16>)] = [
        ("Sentinels & UDF", 0 ... 255),
        ("Data Processing — Immediate", 256 ... 1023),
        ("Branches, Exception, System", 1024 ... 2047),
        ("Loads & Stores", 2048 ... 4095),
        ("Data Processing — Register", 4096 ... 6143),
        ("SIMD & Floating-Point", 6144 ... 12287),
        ("Crypto + Apple Extensions", 12288 ... 16383),
        ("SVE / SVE2 tier", 16384 ... 28671),
        ("SME / SME2 tier", 28672 ... 40959),
    ]
}

extension Mnemonic: CustomStringConvertible {
    /// Canonical lowercase name (`"add"`, `"ldp"`, `"b.cond"`).
    ///
    /// Total: sentinels return fixed census labels and unallocated raw values
    /// return `"?<raw>"`. These are census labels, not assembly — the rendering
    /// of a whole instruction is ``Instruction/text``.
    public var name: String {
        guard let bytes = nameBytes else { return "?\(rawValue)" }
        return bytes.withUTF8Buffer { String(decoding: $0, as: UTF8.self) }
    }

    /// The mnemonic's canonical spelling as a compile-time literal, or `nil`
    /// for a raw value with no declared constant.
    var nameBytes: StaticString? {
        switch rawValue {
        case 0 ... 255: Mnemonic.sentinelName(self)
        case 256 ... 1023: Mnemonic.dataProcessingImmediateName(self)
        case 1024 ... 2047: Mnemonic.branchesExceptionSystemName(self)
        case 2048 ... 4095: Mnemonic.loadsAndStoresName(self)
        case 4096 ... 6143: Mnemonic.dataProcessingRegisterName(self)
        case 6144 ... 12287: Mnemonic.simdAndFPName(self)
        case 12288 ... 16383: Mnemonic.cryptoAppleExtensionsName(self)
        case 16384 ... 16468: SVEPredicateControlCanonicalizer.name(self)
        case 16469 ... 16626: SVEIntegerCanonicalizer.name(self)
        case 16627 ... 16683: SVEFloatingPointCanonicalizer.name(self)
        case 16684 ... 16801: SVEPermuteMemoryCanonicalizer.name(self)
        case 28672 ... 28688: SMECanonicalizer.name(self)
        case 28689 ... 28739: SME2Canonicalizer.name(self)
        default: nil
        }
    }

    /// Same as ``name``.
    @inlinable
    public var description: String {
        name
    }

    /// Names for the sentinel range (0...255).
    static func sentinelName(_ m: Mnemonic) -> StaticString? {
        switch m {
        case .undefined: "undefined"
        case .dataMarker: "data"
        case .truncatedTail: "truncated"
        case .udf: "udf"
        default: nil
        }
    }
}

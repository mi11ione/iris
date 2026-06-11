// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The two architectures `iris` decodes, as selected by `--arch`.
///
/// On a fat binary the selection picks the matching slice; absent an
/// explicit selection the default preference order is ``arm64e`` first,
/// then ``arm64`` (the best slice for an Apple-silicon host). On a thin
/// binary an explicit selection that does not match the file's
/// architecture is an availability error.
@frozen
public enum ArchSelection: String, Sendable, Hashable, CaseIterable {
    /// Plain ARM64 (`CPU_SUBTYPE_ARM64_ALL` or `CPU_SUBTYPE_ARM64_V8`).
    case arm64
    /// ARM64E (`CPU_SUBTYPE_ARM64E`) — implies pointer-authentication decode.
    case arm64e

    /// The decode features a slice of this architecture implies.
    @inlinable
    public var features: Features {
        switch self {
        case .arm64: []
        case .arm64e: .arm64e
        }
    }
}

/// Human-readable architecture names for `(cputype, cpusubtype)` pairs,
/// used when listing a fat binary's available slices in diagnostics.
public enum ArchitectureName {
    /// `CPU_TYPE_ARM64` (`CPU_TYPE_ARM | CPU_ARCH_ABI64`).
    public static let cpuTypeARM64: Int32 = 0x0100_000C

    /// `CPU_SUBTYPE_ARM64E` in the subtype's low feature byte.
    public static let cpuSubtypeARM64E: UInt8 = 2

    /// Render a `(cputype, cpusubtype)` pair the way `lipo -info` would:
    /// known pairs get their canonical short name, anything else a
    /// `cputype(N,M)` form that still identifies the slice.
    public static func name(cputype: Int32, cpusubtype: Int32) -> String {
        let variant = UInt8(truncatingIfNeeded: cpusubtype & 0xFF)
        switch cputype {
        case cpuTypeARM64:
            switch variant {
            case 0: return "arm64"
            case 1: return "arm64v8"
            case cpuSubtypeARM64E: return "arm64e"
            default: return "arm64 (subtype \(variant))"
            }
        case 0x0200_000C: return "arm64_32"
        case 0x0100_0007: return "x86_64"
        case 0x0000_0007: return "i386"
        case 0x0000_000C: return "arm"
        default: return "cputype(\(cputype),\(cpusubtype))"
        }
    }

    /// Whether the pair is a decodable ARM64 flavor, and which selection
    /// it satisfies. `nil` for any non-ARM64 cputype or unknown subtype.
    public static func selection(cputype: Int32, cpusubtype: Int32) -> ArchSelection? {
        guard cputype == cpuTypeARM64 else { return nil }
        switch UInt8(truncatingIfNeeded: cpusubtype & 0xFF) {
        case 0, 1: return .arm64
        case cpuSubtypeARM64E: return .arm64e
        default: return nil
        }
    }
}

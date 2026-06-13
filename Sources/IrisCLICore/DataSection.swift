// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One non-code, file-backed section of a walked Mach-O slice: the
/// `__cstring` / `__const` / `__data` content that an address-forming
/// instruction in the code can point at. Code sections feed the
/// disassembler; data sections feed the referenced-data annotation,
/// which resolves a PC-relative target to its containing section, the
/// C string it lands on, or the data symbol at it.
///
/// The walker establishes `fileOffset + byteCount <= slice.size` at
/// construction (clamping a lying section header), so ``cString(at:)``
/// is total: an out-of-range read returns `nil`, never a crash.
@frozen
public struct DataSection: Sendable {
    /// Parent segment name (`__TEXT`, `__DATA`, `__DATA_CONST`).
    public let segmentName: String
    /// Section name (`__cstring`, `__const`, `__data`, …).
    public let sectionName: String
    /// VM address of the section's first byte.
    public let address: UInt64
    /// Byte offset of the section's content within the slice.
    public let fileOffset: UInt64
    /// Content length in bytes (clamped to the slice when the header lies).
    public let byteCount: UInt64
    /// Whether the section holds C strings (`S_CSTRING_LITERALS`), the
    /// sections whose target reads back as a quoted string.
    public let isCStringLiteral: Bool

    @usableFromInline let slice: MappedFile

    @usableFromInline
    init(
        segmentName: String,
        sectionName: String,
        address: UInt64,
        fileOffset: UInt64,
        byteCount: UInt64,
        isCStringLiteral: Bool,
        slice: MappedFile,
    ) {
        self.segmentName = segmentName
        self.sectionName = sectionName
        self.address = address
        self.fileOffset = fileOffset
        self.byteCount = byteCount
        self.isCStringLiteral = isCStringLiteral
        self.slice = slice
    }

    /// `__TEXT,__cstring`-style display name.
    @inlinable
    public var displayName: String {
        "\(segmentName),\(sectionName)"
    }

    /// Whether `address` lies in the section's VM range, evaluated
    /// modulo 2^64, total even for a hostile section wrapping the top
    /// of the address space.
    @inlinable
    public func containsAddress(_ address: UInt64) -> Bool {
        address &- self.address < byteCount
    }

    /// The NUL-terminated C string at VM address `address`, or `nil` when
    /// `address` is outside the section or no terminator is found before
    /// its end. Zero-copy bounds-checked read through the mapped slice.
    ///
    /// The walker establishes `fileOffset + byteCount <= slice.size` (an
    /// `Int`) at construction, and `containsAddress` bounds
    /// `offsetInSection < byteCount`, so `filePosition` and `remaining`
    /// both fit an `Int` once the guard passes. `readCString` bounds-checks
    /// the position against the mapping regardless, so a regressed proof
    /// degrades to `nil`, never an out-of-range read.
    public func cString(at address: UInt64) -> String? {
        guard containsAddress(address) else { return nil }
        let offsetInSection = address &- self.address
        let position = Int(truncatingIfNeeded: fileOffset &+ offsetInSection)
        let maxLength = Int(truncatingIfNeeded: byteCount &- offsetInSection)
        return withExtendedLifetime(slice) {
            slice.readCString(at: position, maxLength: maxLength)
        }
    }
}

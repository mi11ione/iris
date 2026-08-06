// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One executable section of a walked Mach-O slice.
@frozen
public struct CodeSection: Sendable {
    /// Parent segment name (`__TEXT`).
    public let segmentName: String
    /// Section name (`__text`, `__stubs`, …).
    public let sectionName: String
    /// VM address of the section's first byte.
    public let address: UInt64
    /// Byte offset of the section's content within the slice.
    public let fileOffset: UInt64
    /// Content length in bytes (clamped to the slice when the header lies).
    public let byteCount: UInt64
    /// Data-in-code spans intersecting this section, rebased so that offset 0
    /// is the section's first byte.
    public let dataInCode: [DataInCodeSpan]

    @usableFromInline let slice: MappedFile

    @usableFromInline
    init(
        segmentName: String,
        sectionName: String,
        address: UInt64,
        fileOffset: UInt64,
        byteCount: UInt64,
        dataInCode: [DataInCodeSpan],
        slice: MappedFile,
    ) {
        self.segmentName = segmentName
        self.sectionName = sectionName
        self.address = address
        self.fileOffset = fileOffset
        self.byteCount = byteCount
        self.dataInCode = dataInCode
        self.slice = slice
    }

    /// `__TEXT,__text`-style display name.
    @inlinable
    public var displayName: String {
        "\(segmentName),\(sectionName)"
    }

    /// Whether `address` lies in the section's VM range, evaluated modulo
    /// 2^64.
    @inlinable
    public func containsAddress(_ address: UInt64) -> Bool {
        address &- self.address < byteCount
    }

    /// Decode the section's bytes.
    public func instructions(features: Features) -> InstructionStream {
        withExtendedLifetime(slice) {
            let start = slice.unsafeBaseAddress.advanced(by: Int(fileOffset))
            let buffer = UnsafeRawBufferPointer(start: start, count: Int(byteCount))
            return InstructionStream(
                bytes: buffer,
                at: address,
                features: features,
                dataInCode: dataInCode,
            )
        }
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One executable section of a walked Mach-O slice: the
/// `S_ATTR_PURE_INSTRUCTIONS` / `S_ATTR_SOME_INSTRUCTIONS` content the
/// CLI disassembles, with its data-in-code spans already rebased into the
/// section's own buffer space.
///
/// The walker establishes the bounds invariant
/// `fileOffset + byteCount <= slice.size` at construction (clamping and
/// diagnosing lying section headers), so ``instructions(features:)`` is
/// total — it never re-fails on bounds.
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
    /// Data-in-code spans intersecting this section, rebased so that
    /// offset 0 is the section's first byte — the exact shape
    /// ``InstructionStream/init(bytes:at:features:dataInCode:)`` accepts.
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

    /// Whether `address` lies in the section's VM range, evaluated
    /// modulo 2^64 — total even for a hostile section wrapping the top
    /// of the address space, matching the stream's address model.
    @inlinable
    public func containsAddress(_ address: UInt64) -> Bool {
        address &- self.address < byteCount
    }

    /// Decode the section's bytes. Zero-copy: the instruction stream is
    /// built directly over the mapped region (kept alive for the call),
    /// with ``dataInCode`` marking embedded data words.
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

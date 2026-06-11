// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Copied and trimmed from Aperture's IO/MappedFile.swift: the synthesized
// heap-backed constructor and Darwin-only resilience flags are dropped
// (the latter kept behind a platform check), everything else is the same
// proven bounds-checked read substrate the parent pipeline uses.

#if canImport(Darwin)
    import Darwin
#else
    import Glibc
#endif

/// A safe, zero-copy, bounds-checked view over a file's bytes.
///
/// `MappedFile` opens a file at construction and memory-maps it read-only,
/// then exposes typed reads, buffer views, string reads, and sub-range
/// windows over the resulting region. Every read is bounds-checked; reads
/// at out-of-range offsets return `nil` instead of dereferencing memory.
///
/// The mapping is owned by the value's underlying class instance and is
/// unmapped exactly once, when the last `MappedFile` referencing it is
/// deallocated. Sub-range views constructed via ``subFile(at:length:)``
/// share the underlying mapping; they are pure pointer arithmetic and
/// keep the mapping alive transitively.
@frozen
public struct MappedFile: Sendable {
    @usableFromInline let mapping: Mapping
    @usableFromInline let windowOffset: Int
    @usableFromInline let windowLength: Int
    @usableFromInline let originPath: String

    /// Maps the file at `path` into memory and constructs a `MappedFile`
    /// over its full contents.
    ///
    /// The file must be a regular file with size strictly greater than
    /// zero, readable by the calling user. Symlinks are followed
    /// transparently. The file descriptor is closed before this
    /// initializer returns; the kernel keeps the mapping alive via the
    /// underlying inode regardless of any later rename, unlink, or close.
    ///
    /// - Parameter path: filesystem path, absolute or relative.
    /// - Returns: `nil` if the file does not exist, is not a regular file,
    ///   is empty, is permission-restricted, or if `open`, `fstat`, or
    ///   `mmap` fails for any reason.
    public init?(path: String) {
        let fd = path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NONBLOCK) }
        guard fd >= 0 else { return nil }

        var st = stat()
        _ = fstat(fd, &st)

        guard (st.st_mode & S_IFMT) == S_IFREG else {
            close(fd)
            return nil
        }
        let size = Int(st.st_size)
        guard size > 0 else {
            close(fd)
            return nil
        }

        #if canImport(Darwin)
            let flags = MAP_PRIVATE | MAP_RESILIENT_CODESIGN | MAP_RESILIENT_MEDIA
        #else
            let flags = MAP_PRIVATE
        #endif
        let raw = mmap(nil, size, PROT_READ, flags, fd, 0)
        close(fd)

        guard let raw, raw != UnsafeMutableRawPointer(bitPattern: -1) else {
            return nil
        }

        self.init(
            mapping: Mapping(baseAddress: UnsafeRawPointer(raw), mappingSize: size),
            windowOffset: 0,
            windowLength: size,
            originPath: path,
        )
    }

    @usableFromInline
    init(
        mapping: Mapping,
        windowOffset: Int,
        windowLength: Int,
        originPath: String,
    ) {
        self.mapping = mapping
        self.windowOffset = windowOffset
        self.windowLength = windowLength
        self.originPath = originPath
    }

    /// Number of bytes visible through this `MappedFile`. Equals the
    /// file's size for a root mapping, the window length for sub-views.
    @inlinable @inline(__always)
    public var size: Int {
        windowLength
    }

    /// Path passed to ``init(path:)``; sub-views inherit the parent's path.
    @inlinable @inline(__always)
    public var path: String {
        originPath
    }

    /// Base address of the visible window's first byte. Valid for the
    /// lifetime of this value or any copy of it; use
    /// `withExtendedLifetime(_:_:)` when escaping the pointer past a
    /// local scope.
    @inlinable @inline(__always)
    public var unsafeBaseAddress: UnsafeRawPointer {
        mapping.baseAddress.advanced(by: windowOffset)
    }

    /// Reads a value of type `T` at the given byte offset. Bounds-checked:
    /// out-of-range offsets return `nil` without dereferencing memory; any
    /// source alignment is permitted.
    @inlinable
    public func read<T: BitwiseCopyable>(at offset: Int, as _: T.Type = T.self) -> T? {
        let s = MemoryLayout<T>.size
        let end = offset &+ s
        guard offset >= 0, end >= offset, end <= windowLength else { return nil }
        let p = mapping.baseAddress.advanced(by: windowOffset + offset)
        return p.loadUnaligned(fromByteOffset: 0, as: T.self)
    }

    /// Invokes `body` with an `UnsafeRawBufferPointer` covering `length`
    /// bytes starting at `offset`, and returns the body's result. The
    /// buffer is a view into the underlying mapping (no copy), valid only
    /// for the duration of the closure. Out-of-bounds ranges return `nil`
    /// without invoking the body.
    @inlinable
    public func withBytes<R>(
        at offset: Int,
        length: Int,
        _ body: (UnsafeRawBufferPointer) -> R,
    ) -> R? {
        guard offset >= 0, length >= 0 else { return nil }
        let end = offset &+ length
        guard end >= offset, end <= windowLength else { return nil }
        let p = mapping.baseAddress.advanced(by: windowOffset + offset)
        let buffer = UnsafeRawBufferPointer(start: p, count: length)
        return body(buffer)
    }

    /// Reads a null-terminated UTF-8 string starting at `offset`, scanning
    /// at most `maxLength` bytes for a terminating NUL. Invalid sequences
    /// are repaired with U+FFFD. Returns `nil` if `offset` is out of
    /// range, `maxLength <= 0`, or no NUL is found within the scanned region.
    @inlinable
    public func readCString(at offset: Int, maxLength: Int) -> String? {
        guard offset >= 0, maxLength > 0, offset < windowLength else { return nil }
        let remaining = windowLength - offset
        let effective = Swift.min(maxLength, remaining)
        let basePtr = mapping.baseAddress.advanced(by: windowOffset + offset)
        let buffer = UnsafeRawBufferPointer(start: basePtr, count: effective)
        guard let nulIndex = buffer.firstIndex(of: 0) else { return nil }
        let strBuf = UnsafeRawBufferPointer(start: basePtr, count: nulIndex)
        return String(decoding: strBuf, as: UTF8.self)
    }

    /// Reads a fixed-length UTF-8 string at `offset`, stopping at the
    /// first NUL byte within the `length`-byte window if present — the
    /// shape of Mach-O's NUL-padded 16-byte `segname`/`sectname` fields.
    /// Returns `nil` if the window is out of bounds.
    @inlinable
    public func readFixedString(at offset: Int, length: Int) -> String? {
        guard offset >= 0, length >= 0 else { return nil }
        let end = offset &+ length
        guard end >= offset, end <= windowLength else { return nil }
        if length == 0 { return "" }
        let basePtr = mapping.baseAddress.advanced(by: windowOffset + offset)
        let window = UnsafeRawBufferPointer(start: basePtr, count: length)
        let stopAt = window.firstIndex(of: 0) ?? length
        let strBuf = UnsafeRawBufferPointer(start: basePtr, count: stopAt)
        return String(decoding: strBuf, as: UTF8.self)
    }

    /// Returns a sub-range view of this `MappedFile` as a new `MappedFile`
    /// sharing the underlying mapping (no copy). Sub-views compose and may
    /// outlive the parent value. Returns `nil` when the range exceeds
    /// `self`'s ``size``.
    @inlinable
    public func subFile(at offset: Int, length: Int) -> MappedFile? {
        guard offset >= 0, length >= 0 else { return nil }
        let end = offset &+ length
        guard end >= offset, end <= windowLength else { return nil }
        return MappedFile(
            mapping: mapping,
            windowOffset: windowOffset + offset,
            windowLength: length,
            originPath: originPath,
        )
    }

    /// Backing class for the mmap'd region, bound to the deallocation
    /// event so `munmap` runs exactly once when the last referencing
    /// `MappedFile` is dropped.
    @usableFromInline
    final class Mapping: Sendable {
        @usableFromInline nonisolated(unsafe) let baseAddress: UnsafeRawPointer
        @usableFromInline let mappingSize: Int

        @usableFromInline
        init(baseAddress: UnsafeRawPointer, mappingSize: Int) {
            self.baseAddress = baseAddress
            self.mappingSize = mappingSize
        }

        deinit {
            _ = munmap(UnsafeMutableRawPointer(mutating: baseAddress), mappingSize)
        }
    }
}

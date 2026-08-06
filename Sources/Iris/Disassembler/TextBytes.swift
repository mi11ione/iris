// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Growable UTF-8 byte buffer.
///
/// Public because the CLI renders into one: assembling a listing line through
/// `String` costs the same per-token bookkeeping this type exists to remove,
/// one layer up and over a whole binary at a time.
@frozen
public struct TextBytes: ~Copyable {
    @usableFromInline var base: UnsafeMutablePointer<UInt8>
    /// Bytes written. Settable so a formatter can roll back a separator it
    /// turned out not to need.
    public var count: Int
    @usableFromInline var capacity: Int
    /// False while the storage belongs to the caller (see
    /// ``init(scratch:capacity:)``).
    @usableFromInline var ownsStorage: Bool

    /// Render into storage the caller already has, so only the final `String`
    /// allocates. If the text outgrows the scratch this type moves to heap
    /// storage and renders in full rather than truncating. `scratch` must be
    /// non-empty.
    public init(scratch: UnsafeMutablePointer<UInt8>, capacity: Int) {
        base = scratch
        count = 0
        self.capacity = capacity
        ownsStorage = false
    }

    /// Heap storage this buffer owns, for a render that spans many records
    /// and reuses one buffer rather than one scratch per record.
    public init(capacity: Int) {
        base = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        count = 0
        self.capacity = capacity
        ownsStorage = true
    }

    deinit {
        if ownsStorage { base.deallocate() }
    }

    @inline(__always)
    public mutating func reserve(_ additional: Int) {
        let needed = count &+ additional
        if needed > capacity { grow(to: needed) }
    }

    /// Move to heap storage large enough for `needed` bytes, copying what
    /// has been written. Reached by the handful of scalable multi-vector
    /// forms whose text outgrows the stack scratch.
    public mutating func grow(to needed: Int) {
        var next = capacity &* 2
        if next < needed { next = needed }
        let fresh = UnsafeMutablePointer<UInt8>.allocate(capacity: next)
        fresh.update(from: base, count: count)
        if ownsStorage { base.deallocate() }
        base = fresh
        capacity = next
        ownsStorage = true
    }

    @inline(__always)
    public mutating func put(_ byte: UInt8) {
        reserve(1)
        base[count] = byte
        count &+= 1
    }

    /// Append a compile-time literal. `StaticString` carries a pointer and
    /// a length and is not a heap object, so this is a length check and a
    /// copy with no allocation, no retain and no release.
    @inline(__always)
    public mutating func put(_ literal: StaticString) {
        let length = literal.utf8CodeUnitCount
        reserve(length)
        let destination = base.advanced(by: count)
        if length <= 16 {
            let source = literal.utf8Start
            for offset in 0 ..< length {
                destination[offset] = source[offset]
            }
        } else {
            destination.update(from: literal.utf8Start, count: length)
        }
        count &+= length
    }

    /// Append an existing `String`'s UTF-8. Deliberately not named `put`: with
    /// both overloads spelled `put`, Swift resolves every string literal to the
    /// `String` one, routing the literals this type exists to make cheap through
    /// `withUTF8`.
    @inline(__always)
    public mutating func putString(_ text: String) {
        var copy = text
        copy.withUTF8 { source in
            reserve(source.count)
            if let start = source.baseAddress, source.count > 0 {
                base.advanced(by: count).update(from: start, count: source.count)
                count &+= source.count
            }
        }
    }

    /// Append `value` in decimal. Digits are generated into a stack tuple
    /// and copied once; there is no intermediate `String` and no call into
    /// the stdlib's generic radix formatter.
    @inline(__always)
    public mutating func putDecimal(_ value: UInt64) {
        if value < 10 {
            put(UInt8(ascii: "0") &+ UInt8(value))
            return
        }
        var digits = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
                      UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
                      UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))
        var written = 0
        withUnsafeMutableBytes(of: &digits) { raw in
            var remaining = value
            var index = raw.count
            while remaining > 0 {
                index &-= 1
                raw[index] = UInt8(ascii: "0") &+ UInt8(remaining % 10)
                remaining /= 10
            }
            written = raw.count &- index
            reserve(written)
            base.advanced(by: count).update(
                from: raw.baseAddress!.advanced(by: index).assumingMemoryBound(to: UInt8.self),
                count: written,
            )
        }
        count &+= written
    }

    /// Signed decimal, with the same `-` placement `"\(value)"` produces.
    @inline(__always)
    public mutating func putDecimal(_ value: Int64) {
        if value < 0 {
            put(UInt8(ascii: "-"))
            putDecimal(value.magnitude)
        } else {
            putDecimal(UInt64(value))
        }
    }

    /// Lowercase hex, no leading zeros — what `String(value, radix: 16)`
    /// gives.
    @inline(__always)
    public mutating func putHex(_ value: UInt64) {
        if value < 16 {
            put(TextBytes.hexDigit(UInt8(value)))
            return
        }
        var nibbles = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
                       UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
                       UInt8(0), UInt8(0))
        var written = 0
        withUnsafeMutableBytes(of: &nibbles) { raw in
            var remaining = value
            var index = raw.count
            while remaining > 0 {
                index &-= 1
                raw[index] = TextBytes.hexDigit(UInt8(remaining & 0xF))
                remaining >>= 4
            }
            written = raw.count &- index
            reserve(written)
            base.advanced(by: count).update(
                from: raw.baseAddress!.advanced(by: index).assumingMemoryBound(to: UInt8.self),
                count: written,
            )
        }
        count &+= written
    }

    @inline(__always)
    public static func hexDigit(_ nibble: UInt8) -> UInt8 {
        nibble < 10 ? UInt8(ascii: "0") &+ nibble : UInt8(ascii: "a") &+ (nibble &- 10)
    }

    /// The bytes written so far, as a `String` — one construction per render.
    /// `String(decoding:as:)` repairs invalid UTF-8, so this is byte-exact only
    /// because every byte written above is ASCII by construction.
    public func makeString() -> String {
        String(decoding: UnsafeBufferPointer(start: base, count: count), as: UTF8.self)
    }
}

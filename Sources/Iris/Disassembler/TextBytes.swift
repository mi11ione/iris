// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// A UTF-8 byte buffer for canonical disassembly text, and the reason it is
// not a `String`.
//
// Once the per-record allocations are gone, what remains in a rendering
// profile is almost entirely `String`'s own machinery rather than the work
// of rendering: `_StringGuts.append`, the unused-capacity and
// prepare-for-append-in-place pair, the count-and-flags update, a
// uniqueness check per append, small-versus-native form branching, and
// bridge-object reference counting. Roughly a third of the cost exists
// because the intermediate is a `String`.
//
// None of it is needed here. Canonical disassembly text is ASCII by
// construction — every byte a canonicalizer emits comes from a literal, a
// register name, a decimal digit or a hex digit — and every consumer
// either compares it or writes it out. So this buffer is bytes with a
// cursor: a bounds check and a store per byte, no flags, no forms, no
// reference counting.
//
// It owns raw storage rather than wrapping `[UInt8]` deliberately.
// `Array`'s append is cheaper than `String`'s but still pays a uniqueness
// check and a capacity check per call, and those are part of what this
// type exists to remove.

/// Growable UTF-8 byte buffer.
///
/// Public because the CLI renders into one: a listing line is an address
/// column, a raw word, canonical text and an annotation, and assembling
/// that per line through `String` costs the same per-token bookkeeping
/// this type exists to remove — one layer up, and over a whole binary at
/// a time.
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

    /// Render into storage the caller already has — in practice a
    /// `withUnsafeTemporaryAllocation` scratch, which at this size is the
    /// stack. This is what lets the returning entry point use the byte path
    /// without a heap allocation for the buffer itself; only the final
    /// `String` allocates, and only when it exceeds the bytes Swift keeps
    /// inline. If the text outgrows the scratch this type moves to heap
    /// storage and takes ownership from that point, so a long instruction
    /// renders in full rather than being truncated.
    ///
    /// `scratch` must be non-empty. Every caller is a
    /// `withUnsafeTemporaryAllocation` of a fixed positive capacity, which
    /// the standard library guarantees yields a non-nil base address, so
    /// this takes the pointer and length rather than an optional-bearing
    /// buffer and carries no branch that cannot be taken.
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
        // A byte loop for short literals, `update(from:count:)` for the
        // rest. Everything appended from a literal here is tiny — a
        // register name is two to four bytes, `", "` is two, the longest
        // mnemonic a handful — and `update(from:count:)` bottoms out in a
        // memmove call, which is a large share of the byte path's cost once
        // the `String` machinery is gone. This function is
        // `@inline(__always)` and `utf8CodeUnitCount` is a compile-time
        // constant for a literal, so `length` is known at every call site
        // and the loop unrolls to exactly that many stores.
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

    /// Append an existing `String`'s UTF-8. Used where a value still
    /// arrives as a `String` — a mnemonic table, a delegated formatter — so
    /// the byte path can be adopted one family at a time.
    ///
    /// Deliberately NOT named `put`: with both overloads spelled `put`,
    /// Swift resolves every string *literal* to the `String` one, which
    /// silently routes the literals this type exists to make cheap through
    /// `withUTF8` instead of the pointer-and-length path.
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
            // `magnitude`, not `-value`: negating `Int64.min` traps.
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

    /// The bytes written so far, as a `String`. One construction at the end
    /// of a whole render rather than one per operand.
    ///
    /// `String(decoding:as:)` repairs invalid UTF-8 to U+FFFD, so this is
    /// byte-exact only because every byte written above is ASCII by
    /// construction: literals, register names, decimal digits, hex digits.
    public func makeString() -> String {
        String(decoding: UnsafeBufferPointer(start: base, count: count), as: UTF8.self)
    }
}

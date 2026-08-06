// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A condition the decode layer surfaced rather than silently absorbing —
/// the carrier of "silent skip, never silent guess".
///
/// Route on ``Kind``, not on the presence of a diagnostic: some kinds are
/// provenance, not malformation.
@frozen
public struct Diagnostic: Sendable, Hashable {
    /// The category of condition observed, with its position and detail
    /// carried as typed payload.
    public let kind: Kind

    /// Construct a Diagnostic with the given kind.
    @inlinable
    public init(kind: Kind) {
        self.kind = kind
    }

    /// Byte offset into the decoded buffer where the condition was
    /// observed, projected from the kind's payload; `nil` when a kind
    /// carries no position.
    @inlinable
    public var bufferOffset: UInt64? {
        switch kind {
        case let .dataInCodeSpanEncountered(_, offset, _):
            offset
        case let .addressSpaceWrapped(offset):
            offset
        }
    }

    @frozen
    public enum Kind: Sendable, Hashable {
        /// A caller-provided data-in-code span intersected the buffer, so the
        /// stream emitted `.dataMarker` records for every word it covered. The
        /// span kind is preserved here so consumers can tell raw `.data` from
        /// the jump-table kinds without re-querying the span list. `offset` and
        /// `length` echo the span as provided.
        case dataInCodeSpanEncountered(kind: DataInCodeSpan.Kind, offset: UInt64, length: UInt64)

        /// `baseAddress + offset` exceeded `UInt64.max` during decode;
        /// record addresses from `offset` on are wrapped modulo 2^64.
        /// Emitted once per stream, carrying the buffer offset of the
        /// first record whose address wrapped.
        case addressSpaceWrapped(offset: UInt64)
    }
}

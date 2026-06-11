// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A localized record of a condition the decode layer surfaced rather
/// than silently absorbing — informational provenance or malformation,
/// depending on ``Kind``.
///
/// `Diagnostic` is the carrier of "silent skip, never silent guess":
/// every place the decoder would otherwise have to choose between
/// aborting and fabricating data, it instead records a `Diagnostic` and
/// continues. Some `Kind` values carry informational provenance for
/// downstream consumers — see
/// ``Kind/dataInCodeSpanEncountered(kind:offset:length:)``, which
/// preserves the span kind for a caller-provided data-in-code span the
/// decoder consumed but did not consider malformed. Consumers should
/// route on `Kind`, not on the presence of any diagnostic, when
/// distinguishing malformations from provenance events.
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
        /// A caller-provided data-in-code span intersected the buffer
        /// being decoded, so the stream emitted `.dataMarker` records
        /// for every 4-byte word the span covered. The span kind is
        /// preserved here on the stream's diagnostics so downstream
        /// consumers that need to distinguish raw `.data` from
        /// `.jumpTable8`/`16`/`32`/`.absoluteJumpTable32` can do so
        /// without re-querying the span list. `offset` and `length`
        /// echo the span as provided, in buffer-offset space.
        case dataInCodeSpanEncountered(kind: DataInCodeSpan.Kind, offset: UInt64, length: UInt64)

        /// `baseAddress + offset` exceeded `UInt64.max` during decode;
        /// record addresses from `offset` on are wrapped modulo 2^64.
        /// Emitted once per stream, carrying the buffer offset of the
        /// first record whose address wrapped.
        case addressSpaceWrapped(offset: UInt64)
    }
}

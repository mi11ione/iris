// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// A condition the Mach-O walker surfaced rather than silently absorbing.
///
/// The walker never crashes and never guesses: every malformation it can
/// step around produces one `WalkerDiagnostic` and a degraded-but-honest
/// result (a clamped section, a dropped data-in-code entry, a truncated
/// symbol list). The CLI prints diagnostics to stderr unless `--quiet`.
@frozen
public struct WalkerDiagnostic: Sendable, Hashable, CustomStringConvertible {
    /// The category of condition observed.
    public let kind: Kind
    /// Human-readable specifics (offsets, sizes, names).
    public let detail: String

    @inlinable
    public init(kind: Kind, detail: String) {
        self.kind = kind
        self.detail = detail
    }

    /// Rendered as the CLI prints it: `warning: <kind>: <detail>`.
    public var description: String {
        "warning: \(kind.label): \(detail)"
    }

    /// Walker malformation / degradation categories.
    @frozen
    public enum Kind: Sendable, Hashable {
        /// A `fat_arch` entry's byte range falls outside the file; the
        /// slice is excluded from selection.
        case fatSliceOutOfBounds
        /// A load command's declared `cmdsize` is too small (< 8) or runs
        /// past the load-command region; the walk stops at the previous
        /// command. Unaligned sizes walk on — reads are alignment-safe.
        case loadCommandInvalid
        /// The load-command region itself exceeds the slice; the walk
        /// covers the in-bounds prefix only.
        case loadCommandRegionTruncated
        /// More than one of a load command the walker expects once
        /// (`LC_SYMTAB`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE`);
        /// the first is used.
        case duplicateLoadCommand
        /// A segment's declared section count does not fit its `cmdsize`;
        /// the in-budget prefix is walked.
        case sectionTableTruncated
        /// A code section's file content runs past the slice; the
        /// section is clamped to the bytes that exist.
        case sectionContentOutOfBounds
        /// A code section declares zero bytes; it is listed nowhere.
        case sectionEmpty
        /// The `LC_DATA_IN_CODE` table region is outside the slice; the
        /// table is ignored.
        case dataInCodeRegionOutOfBounds
        /// The `LC_DATA_IN_CODE` region size is not a multiple of the
        /// 8-byte entry size; the floor prefix is decoded.
        case dataInCodeRegionTruncated
        /// A `data_in_code_entry` lies wholly outside every code
        /// section; the entry is dropped.
        case dataInCodeEntryOutsideCode
        /// A `data_in_code_entry` straddles a code-section boundary; the
        /// in-section part is kept.
        case dataInCodeEntryClamped
        /// The `LC_SYMTAB` symbol or string table region is outside the
        /// slice; symbols are unavailable.
        case symbolTableOutOfBounds
        /// An `nlist_64` entry's name offset is outside the string
        /// table; the symbol is dropped.
        case symbolNameOutOfBounds
        /// The `LC_DYSYMTAB` indirect symbol table region is outside the
        /// slice; stub symbolication is unavailable.
        case indirectSymbolTableOutOfBounds
        /// The `LC_FUNCTION_STARTS` region is outside the slice; function
        /// starts are unavailable.
        case functionStartsOutOfBounds
        /// The `LC_FUNCTION_STARTS` ULEB128 stream is malformed
        /// (truncated mid-value or a value exceeding 64 bits); addresses
        /// decoded before the malformation are kept.
        case functionStartsMalformed
        /// `LC_FUNCTION_STARTS` is present but the slice has no `__TEXT`
        /// segment to anchor the deltas; function starts are unavailable.
        case functionStartsUnanchored

        /// Stable lowercase label used in stderr rendering.
        public var label: String {
            switch self {
            case .fatSliceOutOfBounds: "fat slice out of bounds"
            case .loadCommandInvalid: "load command invalid"
            case .loadCommandRegionTruncated: "load command region truncated"
            case .duplicateLoadCommand: "duplicate load command"
            case .sectionTableTruncated: "section table truncated"
            case .sectionContentOutOfBounds: "section content out of bounds"
            case .sectionEmpty: "section empty"
            case .dataInCodeRegionOutOfBounds: "data-in-code region out of bounds"
            case .dataInCodeRegionTruncated: "data-in-code region truncated"
            case .dataInCodeEntryOutsideCode: "data-in-code entry outside code"
            case .dataInCodeEntryClamped: "data-in-code entry clamped"
            case .symbolTableOutOfBounds: "symbol table out of bounds"
            case .symbolNameOutOfBounds: "symbol name out of bounds"
            case .indirectSymbolTableOutOfBounds: "indirect symbol table out of bounds"
            case .functionStartsOutOfBounds: "function starts out of bounds"
            case .functionStartsMalformed: "function starts malformed"
            case .functionStartsUnanchored: "function starts unanchored"
            }
        }
    }
}

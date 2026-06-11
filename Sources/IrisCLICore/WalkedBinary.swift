// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Everything the CLI needs from one Mach-O slice: its decodable code
/// sections, the symbol index for labels and branch symbolication,
/// function-start addresses for grouping, the decode features its
/// architecture implies, and every malformation the walk surfaced.
@frozen
public struct WalkedBinary: Sendable {
    /// Path the binary was opened from.
    public let path: String
    /// Selected slice's architecture name (`arm64`, `arm64e`, …).
    public let architecture: String
    /// Decode features the slice's architecture implies.
    public let features: Features
    /// Executable sections in load-command walk order.
    public let codeSections: [CodeSection]
    /// Defined symbols, address-indexed.
    public let symbols: SymbolIndex
    /// Ascending `LC_FUNCTION_STARTS` addresses; empty when absent.
    public let functionStarts: [UInt64]
    /// Imported-symbol name keyed by `__stubs`/`__auth_stubs` entry VM
    /// address; empty when the binary has no symbol stubs. A branch whose
    /// target is one of these addresses calls the named import.
    public let stubTargets: [UInt64: String]
    /// Malformations stepped around during the walk.
    public let diagnostics: [WalkerDiagnostic]

    public init(
        path: String,
        architecture: String,
        features: Features,
        codeSections: [CodeSection],
        symbols: SymbolIndex,
        functionStarts: [UInt64],
        stubTargets: [UInt64: String] = [:],
        diagnostics: [WalkerDiagnostic],
    ) {
        self.path = path
        self.architecture = architecture
        self.features = features
        self.codeSections = codeSections
        self.symbols = symbols
        self.functionStarts = functionStarts
        self.stubTargets = stubTargets
        self.diagnostics = diagnostics
    }
}

/// Result of walking a path: a usable binary, or one of the typed
/// failures the CLI maps to its exit codes (2 for
/// unreadable/not-Mach-O, 3 for architecture unavailability).
@frozen
public enum WalkOutcome: Sendable {
    /// A decodable slice was selected and walked.
    case binary(WalkedBinary)
    /// The path could not be opened or mapped.
    case unreadable(detail: String)
    /// The bytes are not a (64-bit) Mach-O or fat container.
    case notMachO(detail: String)
    /// The container holds no slice satisfying the requested (or
    /// default) architecture selection; `available` names every slice
    /// present.
    case archUnavailable(requested: ArchSelection?, available: [String])
}

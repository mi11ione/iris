// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Resolves a branch/call target VM address to the name of what it
/// reaches: an imported function through a `__stubs` entry, a symbol
/// exactly at the target, or the closest preceding symbol as
/// `name+0x<delta>` (only within one code section, so a cross-section
/// delta never fabricates locality). Shared by the listing (which wraps
/// the name as `symbol stub for: …` / `; <name>`) and `--json` (which
/// emits the bare `targetSymbol`), so both render one resolution.
@frozen
public struct BranchSymbolizer: Sendable {
    /// Defined symbols, address-indexed.
    public let symbols: SymbolIndex
    /// Every code section (for the same-section locality check).
    public let sections: [CodeSection]
    /// Imported-symbol name keyed by stub VM address.
    public let stubTargets: [UInt64: String]

    @inlinable
    public init(symbols: SymbolIndex, sections: [CodeSection], stubTargets: [UInt64: String]) {
        self.symbols = symbols
        self.sections = sections
        self.stubTargets = stubTargets
    }

    /// One resolved branch target.
    @frozen
    public struct Resolution: Sendable, Equatable {
        /// The bare name (`_strcoll`, `_helper`, `_name+0x8`).
        public let name: String
        /// True when `name` is the import a `__stubs` entry forwards to.
        public let isStub: Bool

        @inlinable
        public init(name: String, isStub: Bool) {
            self.name = name
            self.isStub = isStub
        }
    }

    /// Resolve `target`, or `nil` when nothing names it. A stub forwarding
    /// to an import wins; then a symbol exactly at the target; then the
    /// closest preceding symbol in the same section as `name+0x<delta>`.
    @inlinable
    public func resolve(target: UInt64) -> Resolution? {
        if let stubName = stubTargets[target] {
            return Resolution(name: stubName, isStub: true)
        }
        if let exact = symbols.name(at: target) {
            return Resolution(name: exact, isStub: false)
        }
        guard let nearest = symbols.nearest(atOrBefore: target) else { return nil }
        let sameSection = sections.contains { section in
            section.containsAddress(target) && section.containsAddress(nearest.address)
        }
        guard sameSection else { return nil }
        return Resolution(name: nearest.name + "+0x" + String(target &- nearest.address, radix: 16), isStub: false)
    }
}

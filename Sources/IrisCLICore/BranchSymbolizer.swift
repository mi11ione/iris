// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Resolves a branch target address to what it reaches.
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

    /// Resolve `target`, or `nil` when nothing names it.
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

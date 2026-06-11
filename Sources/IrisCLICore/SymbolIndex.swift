// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// Address-keyed view of a Mach-O symbol table, holding exactly what the
/// listing needs: defined symbols' names at their VM addresses, indexed
/// for O(log n) exact and closest-preceding lookup.
///
/// Built from `LC_SYMTAB`'s `nlist_64` entries: debug stabs and undefined
/// symbols are excluded (they carry no in-image address), section-defined
/// and absolute symbols are kept — local and external alike, since both
/// label functions in a listing. When several symbols share an address
/// the first in `nlist_64` order wins, matching `nm`-order conventions.
@frozen
public struct SymbolIndex: Sendable {
    @usableFromInline let addresses: [UInt64]
    @usableFromInline let names: [String]

    /// Build the index from `(address, name)` pairs in `nlist_64` order.
    public init(symbols: [(address: UInt64, name: String)]) {
        var seen: Set<UInt64> = []
        seen.reserveCapacity(symbols.count)
        var pairs: [(UInt64, String)] = []
        pairs.reserveCapacity(symbols.count)
        for symbol in symbols where !seen.contains(symbol.address) {
            seen.insert(symbol.address)
            pairs.append((symbol.address, symbol.name))
        }
        pairs.sort { $0.0 < $1.0 }
        addresses = pairs.map(\.0)
        names = pairs.map(\.1)
    }

    /// The empty index (a stripped binary, or `LC_SYMTAB` absent).
    public static let empty = SymbolIndex(symbols: [])

    /// Number of indexed symbols.
    @inlinable
    public var count: Int {
        addresses.count
    }

    /// Every indexed `(address, name)` pair, ascending by address.
    @inlinable
    public var allSymbols: [(address: UInt64, name: String)] {
        Array(zip(addresses, names))
    }

    /// O(log n) exact-address lookup.
    /// - Returns: the symbol name at exactly `address`, or `nil`.
    @inlinable
    public func name(at address: UInt64) -> String? {
        let i = lowerBound(of: address)
        guard i < addresses.count, addresses[i] == address else { return nil }
        return names[i]
    }

    /// O(log n) closest-preceding lookup: the symbol with the largest
    /// address `<= address`.
    /// - Returns: the `(address, name)` pair, or `nil` when `address`
    ///   precedes every indexed symbol.
    @inlinable
    public func nearest(atOrBefore address: UInt64) -> (address: UInt64, name: String)? {
        var lo = 0
        var hi = addresses.count
        while lo < hi {
            let mid = (lo &+ hi) >> 1
            if addresses[mid] <= address { lo = mid &+ 1 } else { hi = mid }
        }
        guard lo > 0 else { return nil }
        return (addresses[lo &- 1], names[lo &- 1])
    }

    /// All indexed symbols with `range.lowerBound <= address <
    /// range.upperBound`, ascending. O(log n + k).
    public func symbols(in range: Range<UInt64>) -> [(address: UInt64, name: String)] {
        let start = lowerBound(of: range.lowerBound)
        var result: [(UInt64, String)] = []
        var i = start
        while i < addresses.count, addresses[i] < range.upperBound {
            result.append((addresses[i], names[i]))
            i &+= 1
        }
        return result
    }

    /// Smallest index `i` with `addresses[i] >= value`.
    @usableFromInline
    func lowerBound(of value: UInt64) -> Int {
        var lo = 0
        var hi = addresses.count
        while lo < hi {
            let mid = (lo &+ hi) >> 1
            if addresses[mid] < value { lo = mid &+ 1 } else { hi = mid }
        }
        return lo
    }
}

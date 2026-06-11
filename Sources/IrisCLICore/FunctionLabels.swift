// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

/// The function-boundary labels a binary groups its listing under, in
/// ascending address order: every `LC_FUNCTION_STARTS` address (named by
/// its symbol, or `sub_<hex>` when the symbol table is stripped) and
/// every defined symbol address. This is the same label set
/// ``ListingRenderer`` prints as `_name:` / `sub_<hex>:` lines, lifted
/// into a reusable lookup so `--json` can name each instruction's
/// containing function identically.
@frozen
public struct FunctionLabels: Sendable {
    @usableFromInline let addresses: [UInt64]
    @usableFromInline let names: [String]

    /// Build the boundary list from a walked binary's function starts and
    /// symbol index. Function starts win over a same-address symbol-only
    /// boundary (they mark the function's true entry), matching the
    /// listing's label precedence.
    public init(functionStarts: [UInt64], symbols: SymbolIndex) {
        var labels: [UInt64: String] = [:]
        for start in functionStarts {
            labels[start] = symbols.name(at: start) ?? "sub_" + String(start, radix: 16)
        }
        for (address, name) in symbols.allSymbols where labels[address] == nil {
            labels[address] = name
        }
        let sorted = labels.sorted { $0.key < $1.key }
        addresses = sorted.map(\.key)
        names = sorted.map(\.value)
    }

    /// The empty labeling (direct-decode modes, or a binary with neither
    /// function starts nor symbols).
    public static let empty = FunctionLabels(functionStarts: [], symbols: .empty)

    /// Name of the function containing `address` — the label of the
    /// largest boundary at-or-before it, or `nil` when `address` precedes
    /// every boundary (no function owns it).
    @inlinable
    public func containing(_ address: UInt64) -> String? {
        var lo = 0
        var hi = addresses.count
        while lo < hi {
            let mid = (lo &+ hi) >> 1
            if addresses[mid] <= address { lo = mid &+ 1 } else { hi = mid }
        }
        guard lo > 0 else { return nil }
        return names[lo &- 1]
    }
}

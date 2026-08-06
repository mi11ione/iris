// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Renders the human-mode `functions` output.
public enum FunctionSummary {
    /// Right-pad `text` to `width` plain characters (no truncation).
    static func padLeft(_ text: String, to width: Int) -> String {
        text + String(repeating: " ", count: max(width - text.count, 0))
    }

    /// Left-pad `text` to `width` plain characters (right-aligned).
    static func padRight(_ text: String, to width: Int) -> String {
        String(repeating: " ", count: max(width - text.count, 0)) + text
    }

    /// Width of a column.
    static func columnWidth(_ header: String, _ values: [String]) -> Int {
        values.reduce(header.count) { max($0, $1.count) }
    }

    /// Emit the whole summary for `binary`'s `functions`, line by line.
    public static func emit(
        functions: [FunctionView],
        binary: WalkedBinary,
        palette: Palette,
        emit: (String) -> Void,
    ) {
        emit("\(binary.path) (\(binary.architecture)):\n")
        emit("\n")
        guard !functions.isEmpty else {
            emit("(no functions)\n")
            return
        }

        let addressColumn = "address"
        let symbolColumn = "symbol"
        let countColumn = "instructions"
        let callsColumn = "calls"
        let pacColumn = "pac"

        let addresses = functions.map { InstructionText.hex($0.address) }
        let symbols = functions.map(\.symbol)
        let counts = functions.map { String($0.instructionCount) }
        let calls = functions.map { String($0.callCount) }
        let pacs = functions.map { $0.usesPointerAuthentication ? "yes" : "no" }

        let addressWidth = columnWidth(addressColumn, addresses)
        let symbolWidth = columnWidth(symbolColumn, symbols)
        let countWidth = columnWidth(countColumn, counts)
        let callsWidth = columnWidth(callsColumn, calls)
        let pacWidth = columnWidth(pacColumn, pacs)

        let header = padLeft(addressColumn, to: addressWidth) + "  "
            + padLeft(symbolColumn, to: symbolWidth) + "  "
            + padRight(countColumn, to: countWidth) + "  "
            + padRight(callsColumn, to: callsWidth) + "  "
            + padRight(pacColumn, to: pacWidth)
        emit(palette.label(header) + "\n")

        for (offset, function) in functions.enumerated() {
            let address = palette.address(padLeft(addresses[offset], to: addressWidth))
            let symbol = palette.mnemonic(padLeft(function.symbol, to: symbolWidth))
            let count = padRight(counts[offset], to: countWidth)
            let call = padRight(calls[offset], to: callsWidth)
            let pac = padRight(pacs[offset], to: pacWidth)
            emit(address + "  " + symbol + "  " + count + "  " + call + "  " + pac + "\n")
        }
    }
}

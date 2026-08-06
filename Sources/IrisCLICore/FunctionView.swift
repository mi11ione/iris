// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One function-sized unit of a walked binary, the granularity the `functions`
/// verb emits.
@frozen
public struct FunctionView: Sendable {
    /// The function's name.
    public let symbol: String
    /// VM address of the first instruction (the function start).
    public let address: UInt64
    /// Exclusive end VM address.
    public let endAddress: UInt64
    /// The decoded records the span covers, in address order.
    public let instructions: [Instruction]

    @inlinable
    public init(symbol: String, address: UInt64, endAddress: UInt64, instructions: [Instruction]) {
        self.symbol = symbol
        self.address = address
        self.endAddress = endAddress
        self.instructions = instructions
    }

    /// Number of instructions in the function.
    @inlinable
    public var instructionCount: Int {
        instructions.count
    }

    /// How many of the function's instructions are calls (`isCall`).
    @inlinable
    public var callCount: Int {
        instructions.reduce(0) { $0 + ($1.isCall ? 1 : 0) }
    }

    /// Whether any instruction in the function uses pointer authentication
    /// (`usesPointerAuthentication`).
    @inlinable
    public var usesPointerAuthentication: Bool {
        instructions.contains { $0.usesPointerAuthentication }
    }
}

/// Carves a walked binary into ``FunctionView`` units from loader data.
public enum FunctionCarver {
    /// Build the binary's functions, decoding each section once.
    public static func functions(
        of binary: WalkedBinary,
        onStreamDiagnostic: (CodeSection, Diagnostic) -> Void = { _, _ in },
    ) -> [FunctionView] {
        let starts = binary.functionStarts
        var result: [FunctionView] = []
        for section in binary.codeSections {
            let stream = section.instructions(features: binary.features)
            for diagnostic in stream.diagnostics {
                onStreamDiagnostic(section, diagnostic)
            }
            appendFunctions(in: section, stream: stream, starts: starts, symbols: binary.symbols, into: &result)
        }
        return result
    }

    /// Append one section's functions to `result`.
    static func appendFunctions(
        in section: CodeSection,
        stream: InstructionStream,
        starts: [UInt64],
        symbols: SymbolIndex,
        into result: inout [FunctionView],
    ) {
        let sectionEnd = section.address &+ section.byteCount
        let inSection = starts.filter { section.containsAddress($0) }
        guard !inSection.isEmpty else { return }

        var spans: [(start: UInt64, end: UInt64, name: String, records: [Instruction])] = []
        spans.reserveCapacity(inSection.count)
        for (offset, start) in inSection.enumerated() {
            let nextStart = offset + 1 < inSection.count ? inSection[offset + 1] : sectionEnd
            let end = min(nextStart, sectionEnd)
            let name = symbols.name(at: start) ?? "sub_" + String(start, radix: 16)
            spans.append((start, end, name, []))
        }

        let last = spans.count - 1
        var index = 0
        for instruction in stream {
            let address = instruction.address
            while index < last, address >= spans[index + 1].start {
                index += 1
            }
            guard address >= spans[index].start else { continue }
            spans[index].records.append(instruction)
        }

        for span in spans {
            result.append(FunctionView(
                symbol: span.name,
                address: span.start,
                endAddress: span.end,
                instructions: span.records,
            ))
        }
    }
}

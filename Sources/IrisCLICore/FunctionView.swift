// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One function-sized unit of a walked binary, the granularity the
/// `functions` verb emits: a contiguous instruction span bounded by loader
/// data, with the symbol that names it.
///
/// Boundaries come from `LC_FUNCTION_STARTS` and section membership only,
/// never control-flow inference. A function start at `start` owns the
/// records in `[start, min(nextStart, sectionEnd))`, where `nextStart` is
/// the next function start anywhere in the binary and `sectionEnd` is the
/// end of the section `start` falls in. The section clamp is what excludes
/// an adjacent `__auth_stubs`/`__stubs` island (a different section) and
/// any trailing padding past a section, so a function never sweeps in the
/// stub bytes that `group_by(.symbol)` over the per-instruction stream
/// would attribute to the last symbol.
@frozen
public struct FunctionView: Sendable {
    /// The function's name: its symbol-table name, or the `sub_<hex>` form
    /// when only `LC_FUNCTION_STARTS` marks the entry (a stripped binary).
    public let symbol: String
    /// VM address of the first instruction (the function start).
    public let address: UInt64
    /// Exclusive end VM address: `min(nextStart, sectionEnd)`.
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

    /// How many of the function's instructions are calls (`isCall`): BL/BLR
    /// and their authenticated forms. A rollup the human summary reports.
    @inlinable
    public var callCount: Int {
        instructions.reduce(0) { $0 + ($1.isCall ? 1 : 0) }
    }

    /// Whether any instruction in the function uses pointer authentication
    /// (`usesPointerAuthentication`): a PAC prologue, an authenticated
    /// branch/return, or an authenticated load.
    @inlinable
    public var usesPointerAuthentication: Bool {
        instructions.contains { $0.usesPointerAuthentication }
    }
}

/// Carves a walked binary into ``FunctionView`` units from loader data.
///
/// The walk is one pass per code section: function starts inside the
/// section are paired with their end (the next function start, clamped to
/// the section end), then the section's already-decoded records are
/// bucketed into those spans. Sections are visited in load-command order
/// and functions within a section in ascending address, so the emitted
/// order is "address order, sections in load-command order". Records that
/// precede the section's first function start belong to no function and
/// are not emitted (no boundary owns them).
public enum FunctionCarver {
    /// Build the binary's functions, decoding each section once.
    ///
    /// `onStreamDiagnostic` receives each section's decode diagnostics so
    /// the caller can route them to stderr exactly as the listing and the
    /// per-instruction stream do.
    public static func functions(
        of binary: WalkedBinary,
        onStreamDiagnostic: (CodeSection, Diagnostic) -> Void = { _, _ in },
    ) -> [FunctionView] {
        // Global ascending function starts: the end of one function is the
        // next start anywhere in the binary (clamped per section below).
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

    /// Append one section's functions to `result`. A function start in the
    /// section owns `[start, min(nextStart, sectionEnd))`. Records are
    /// walked once in address order and assigned to the active span.
    static func appendFunctions(
        in section: CodeSection,
        stream: InstructionStream,
        starts: [UInt64],
        symbols: SymbolIndex,
        into result: inout [FunctionView],
    ) {
        let sectionEnd = section.address &+ section.byteCount
        // Function starts that fall in this section, ascending (the global
        // list is already sorted, so this is a range filter).
        let inSection = starts.filter { section.containsAddress($0) }
        guard !inSection.isEmpty else { return }

        // Pair each start with its exclusive end and a fresh record bucket.
        var spans: [(start: UInt64, end: UInt64, name: String, records: [Instruction])] = []
        spans.reserveCapacity(inSection.count)
        for (offset, start) in inSection.enumerated() {
            let nextStart = offset + 1 < inSection.count ? inSection[offset + 1] : sectionEnd
            let end = min(nextStart, sectionEnd)
            let name = symbols.name(at: start) ?? "sub_" + String(start, radix: 16)
            spans.append((start, end, name, []))
        }

        // One ascending pass over the section's records. The spans are
        // contiguous and cover `[spans[0].start, sectionEnd)` with no gap
        // (each non-last end equals the next start; the last end is the
        // section end), and the stream is ascending, so a single cursor
        // walks them: advance to the last span whose start is at-or-before
        // the record, then assign. A record before the first start (none
        // in the well-formed case, present when a section's leading bytes
        // precede its first function) is owned by no span and dropped.
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Renders instruction streams as human-grade listings.
@frozen
public struct ListingRenderer: Sendable {
    /// Column at which the `; reads=… writes=…` annotation starts, measured
    /// from the start of the text column.
    public static let semanticsColumn = 44

    /// Symbolication context for file-mode listings; direct-decode streams
    /// render without one.
    @frozen
    public struct Context: Sendable {
        /// The section the rendered instructions belong to.
        public let section: CodeSection
        /// The binary's symbol index.
        public let symbols: SymbolIndex
        /// Every code section of the binary (for same-section checks).
        public let sections: [CodeSection]
        /// Imported-symbol name keyed by stub VM address; a branch to one of
        /// these annotates `symbol stub for: <name>`.
        public let stubTargets: [UInt64: String]
        /// Resolver for the referenced-data annotation (the string /
        /// data-symbol / section an address-forming instruction points at).
        public let referencedData: ReferencedDataResolver

        @inlinable
        public init(
            section: CodeSection,
            symbols: SymbolIndex,
            sections: [CodeSection],
            stubTargets: [UInt64: String] = [:],
            referencedData: ReferencedDataResolver = .empty,
        ) {
            self.section = section
            self.symbols = symbols
            self.sections = sections
            self.stubTargets = stubTargets
            self.referencedData = referencedData
        }

        /// The shared branch-target resolver over this context.
        @inlinable
        var symbolizer: BranchSymbolizer {
            BranchSymbolizer(symbols: symbols, sections: sections, stubTargets: stubTargets)
        }
    }

    /// ANSI palette (identity when color is off).
    public let palette: Palette
    /// Whether each line carries the `--semantics` annotation.
    public let includeSemantics: Bool

    @inlinable
    public init(palette: Palette, includeSemantics: Bool) {
        self.palette = palette
        self.includeSemantics = includeSemantics
    }

    /// Emit the full listing line by line, optionally scoped by
    /// `addressFilter` (`disasm --function` / `--range`).
    public func emitListing(
        for binary: WalkedBinary,
        emit: (String) -> Void,
        addressFilter: (UInt64) -> Bool = { _ in true },
        onStreamDiagnostic: (CodeSection, Diagnostic) -> Void = { _, _ in },
    ) {
        emit("\(binary.path) (\(binary.architecture)):\n")
        for section in binary.codeSections {
            emitSection(
                section, of: binary, emit: emit,
                addressFilter: addressFilter, onStreamDiagnostic: onStreamDiagnostic,
            )
        }
    }

    /// Emit one section's lines.
    func emitSection(
        _ section: CodeSection,
        of binary: WalkedBinary,
        emit: (String) -> Void,
        addressFilter: (UInt64) -> Bool,
        onStreamDiagnostic: (CodeSection, Diagnostic) -> Void,
    ) {
        let stream = section.instructions(features: binary.features)
        for diagnostic in stream.diagnostics {
            onStreamDiagnostic(section, diagnostic)
        }
        let sectionEnd = section.address &+ section.byteCount
        var labels: [UInt64: String] = [:]
        for start in binary.functionStarts where section.containsAddress(start) {
            labels[start] = binary.symbols.name(at: start) ?? "sub_" + String(start, radix: 16)
        }
        for (address, name) in sectionSymbols(of: binary.symbols, in: section) where labels[address] == nil {
            labels[address] = name
        }
        let width = sectionEnd > section.address ? String(sectionEnd &- 1, radix: 16).count : 16
        let context = Context(
            section: section,
            symbols: binary.symbols,
            sections: binary.codeSections,
            stubTargets: binary.stubTargets,
            referencedData: binary.referencedDataResolver,
        )
        var headerEmitted = false
        var out = TextBytes(capacity: Swift.max(4096, stream.records.count * 48))
        func emitSectionHeader() {
            guard !headerEmitted else { return }
            headerEmitted = true
            out.put(UInt8(ascii: "\n"))
            palette.open("1", into: &out)
            out.putString(section.displayName)
            out.put(UInt8(ascii: ":"))
            palette.close(into: &out)
            out.put(UInt8(ascii: "\n"))
        }
        var preceding: Instruction?
        for instruction in stream {
            defer { preceding = instruction }
            guard addressFilter(instruction.address) else { continue }
            emitSectionHeader()
            if let label = labels[instruction.address] {
                out.put(UInt8(ascii: "\n"))
                palette.open("1", into: &out)
                out.putString(label)
                out.put(UInt8(ascii: ":"))
                palette.close(into: &out)
                out.put(UInt8(ascii: "\n"))
            }
            putLine(
                for: instruction, addressWidth: width,
                context: context, preceding: preceding, into: &out,
            )
            out.put(UInt8(ascii: "\n"))
        }
        if out.count > 0 { emit(out.makeString()) }
    }

    /// Emit a bare stream (the direct-decode modes).
    public func emitStream(_ stream: InstructionStream, emit: (String) -> Void) {
        let last = stream.baseAddress &+ (stream.byteCount > 0 ? stream.byteCount &- 1 : 0)
        let width = String(last, radix: 16).count
        var out = TextBytes(capacity: Swift.max(256, stream.records.count * 48))
        for instruction in stream {
            putLine(
                for: instruction, addressWidth: width,
                context: nil, preceding: nil, into: &out,
            )
            out.put(UInt8(ascii: "\n"))
        }
        if out.count > 0 { emit(out.makeString()) }
    }

    /// Render one instruction line (no trailing newline).
    public func line(
        for instruction: Instruction,
        addressWidth: Int,
        context: Context?,
        preceding: Instruction? = nil,
    ) -> String {
        var out = TextBytes(capacity: 128)
        putLine(
            for: instruction, addressWidth: addressWidth,
            context: context, preceding: preceding, into: &out,
        )
        return out.makeString()
    }

    /// The text column.
    func bodyText(
        for instruction: Instruction,
        context: Context?,
        preceding: Instruction? = nil,
    ) -> (plain: String, colored: String) {
        if instruction.isUndefined {
            return (
                instruction.text + " ; undefined",
                palette.data(instruction.text) + palette.annotation(" ; undefined"),
            )
        }
        switch instruction.category {
        case .dataInCodeMarker:
            let kindSuffix = dataInCodeKindName(for: instruction, in: context?.section)
                .map { " ; data-in-code (\($0))" } ?? ""
            return (
                instruction.text + kindSuffix,
                palette.data(instruction.text) + palette.annotation(kindSuffix),
            )
        case .truncatedTail:
            return (
                instruction.text + " ; truncated tail",
                palette.data(instruction.text) + palette.annotation(" ; truncated tail"),
            )
        default:
            let text = InstructionText.absoluteBranchText(instruction)
            let annotation = targetAnnotation(for: instruction, context: context, preceding: preceding).map { " ; " + $0 } ?? ""
            let mnemonic = InstructionText.mnemonicToken(of: text)
            let rest = text.dropFirst(mnemonic.count)
            return (
                text + annotation,
                palette.mnemonic(String(mnemonic)) + String(rest) + palette.annotation(annotation),
            )
        }
    }

    /// The trailing comment for a non-sentinel line, in priority order.
    func targetAnnotation(for instruction: Instruction, context: Context?, preceding: Instruction?) -> String? {
        if let symbol = symbolAnnotation(for: instruction, context: context) {
            return symbol
        }
        if let context, let data = context.referencedData.resolve(instruction, preceding: preceding) {
            return referencedDataComment(data)
        }
        if let pcRelative = instruction.pcRelativeTarget {
            return InstructionText.hex(pcRelative)
        }
        if let character = CharLiteralHint.character(for: instruction) {
            return "'\(character)'"
        }
        return nil
    }

    /// The trailing-comment text for a resolved ``ReferencedData``.
    func referencedDataComment(_ data: ReferencedData) -> String {
        if let string = data.string {
            return InstructionText.quotedString(string)
        }
        if let symbol = data.symbol {
            return symbol
        }
        return data.section
    }

    /// The data-in-code kind covering this word, rendered in the listing's
    /// fixed vocabulary.
    func dataInCodeKindName(for instruction: Instruction, in section: CodeSection?) -> String? {
        guard let section else { return nil }
        let offset = instruction.address &- section.address
        let span = section.dataInCode.first { offset >= $0.offset && offset < $0.offset &+ $0.length }
        return span.map { kindName($0.kind) }
    }

    /// Fixed vocabulary for `DataInCodeSpan/Kind` in annotations.
    public func kindName(_ kind: DataInCodeSpan.Kind) -> String {
        switch kind {
        case .data: "data"
        case .jumpTable8: "jump-table-8"
        case .jumpTable16: "jump-table-16"
        case .jumpTable32: "jump-table-32"
        case .absoluteJumpTable32: "abs-jump-table-32"
        case let .unknown(rawValue): "kind-0x" + String(rawValue, radix: 16)
        }
    }

    /// Branch-target symbolication: a stub forwarding to an import (`symbol
    /// stub for: _name`) takes precedence; otherwise the symbol exactly at the
    /// target, or the closest preceding symbol as `name+0x<delta>`, the latter
    /// only when target and symbol lie in the same code section (cross-section
    /// deltas would fabricate locality).
    func symbolAnnotation(for instruction: Instruction, context: Context?) -> String? {
        guard let context, let target = instruction.branchTarget else { return nil }
        guard let resolution = context.symbolizer.resolve(target: target) else { return nil }
        return resolution.isStub ? "symbol stub for: " + resolution.name : resolution.name
    }

    /// All symbols inside the section's address range, split into two queries
    /// when the range wraps the top of the address space (`Range` cannot
    /// express the wrap, and a hostile vmaddr must not crash the listing).
    func sectionSymbols(of symbols: SymbolIndex, in section: CodeSection) -> [(address: UInt64, name: String)] {
        let end = section.address &+ section.byteCount
        if end > section.address {
            return symbols.symbols(in: section.address ..< end)
        }
        var result = symbols.symbols(in: section.address ..< UInt64.max)
        if let top = symbols.name(at: UInt64.max) {
            result.append((UInt64.max, top))
        }
        result.append(contentsOf: symbols.symbols(in: 0 ..< end))
        return result
    }
}

extension Palette {
    /// Open an escape sequence, or nothing when color is off.
    @inline(__always)
    func open(_ code: StaticString, into out: inout TextBytes) {
        guard enabled else { return }
        out.put("\u{1B}[")
        out.put(code)
        out.put(UInt8(ascii: "m"))
    }

    /// Close the current escape sequence, or nothing when color is off.
    @inline(__always)
    func close(into out: inout TextBytes) {
        guard enabled else { return }
        out.put("\u{1B}[0m")
    }
}

extension InstructionText {
    /// Lowercase hex, zero-padded to at least `width` digits.
    @inline(__always)
    static func putAddress(_ value: UInt64, width: Int, into out: inout TextBytes) {
        var digits = 1
        var probe = value
        while probe >= 16 {
            probe >>= 4; digits += 1
        }
        for _ in digits ..< width {
            out.put(UInt8(ascii: "0"))
        }
        out.putHex(value)
    }

    /// The 8-digit raw-word column.
    @inline(__always)
    static func putWord(_ value: UInt32, into out: inout TextBytes) {
        putAddress(UInt64(value), width: 8, into: &out)
    }
}

public extension ListingRenderer {
    /// Append one rendered line (no trailing newline) to `out`.
    func putLine(
        for instruction: Instruction,
        addressWidth: Int,
        context: Context?,
        preceding: Instruction? = nil,
        into out: inout TextBytes,
    ) {
        palette.open("2", into: &out)
        InstructionText.putAddress(instruction.address, width: addressWidth, into: &out)
        out.put(UInt8(ascii: ":"))
        palette.close(into: &out)
        out.put(UInt8(ascii: " "))
        putWordColumn(for: instruction, into: &out)
        out.put("  ")

        let body = bodyText(for: instruction, context: context, preceding: preceding)
        out.putString(body.colored)
        guard includeSemantics else { return }
        let annotation = SemanticsAnnotation.annotation(for: instruction)
        guard !annotation.isEmpty else { return }
        let padding = max(Self.semanticsColumn - body.plain.count, 1)
        for _ in 0 ..< padding {
            out.put(UInt8(ascii: " "))
        }
        palette.open("90", into: &out)
        out.put("; ")
        out.putString(annotation)
        palette.close(into: &out)
    }

    /// The raw-word column, byte path.
    @inline(__always)
    internal func putWordColumn(for instruction: Instruction, into out: inout TextBytes) {
        let tailBytes = instruction.record.tailByteCount
        guard tailBytes > 0 else {
            InstructionText.putWord(instruction.encoding, into: &out)
            return
        }
        let digits = tailBytes * 2
        InstructionText.putAddress(UInt64(instruction.encoding), width: digits, into: &out)
        for _ in 0 ..< (8 - digits) {
            out.put(UInt8(ascii: " "))
        }
    }
}

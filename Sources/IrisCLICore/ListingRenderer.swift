// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Renders instruction streams as human-grade listings: address / raw
/// word / canonical text columns, function labels, branch-target
/// symbolication, data-in-code annotations, optional per-line semantics,
/// and TTY-aware color.
///
/// Layout, by line kind (alignment is computed on plain text; color is
/// applied after padding, so escapes never disturb columns):
///
///     <path> (<arch>):
///
///     __TEXT,__text:
///
///     _main:
///     100003f70: a9be7bfd   stp x29, x30, [sp, #-32]!
///     100003f80: 94000005   bl 0x100003f94 ; _helper
///     100003f88: 0000002a   .long 0x2a ; data-in-code (jump-table-32)
///
/// Addresses are lowercase hex zero-padded to the width of the
/// section's last address; raw words are 8 hex digits (a truncated
/// tail shows its residual bytes' value at its natural width,
/// space-padded). Direct branches render their absolute target (the
/// library's relative `#offset` form rewritten at presentation level)
/// and gain a `; symbol` annotation when the target resolves, exactly
/// at a symbol, or past one in the same code section (`; _name+0x8`).
/// Labels come from `LC_FUNCTION_STARTS` and the symbol table; a
/// function start without a symbol is labeled `sub_<hex>:`. With
/// semantics enabled, each line is padded to a fixed column and
/// annotated per ``SemanticsAnnotation``.
@frozen
public struct ListingRenderer: Sendable {
    /// Column at which the `; reads=… writes=…` annotation starts,
    /// measured from the start of the text column.
    public static let semanticsColumn = 44

    /// Symbolication context for file-mode listings; direct-decode
    /// streams render without one.
    @frozen
    public struct Context: Sendable {
        /// The section the rendered instructions belong to.
        public let section: CodeSection
        /// The binary's symbol index.
        public let symbols: SymbolIndex
        /// Every code section of the binary (for same-section checks).
        public let sections: [CodeSection]
        /// Imported-symbol name keyed by stub VM address; a branch to one
        /// of these annotates `symbol stub for: <name>`.
        public let stubTargets: [UInt64: String]
        /// Resolver for the referenced-data annotation (the string /
        /// data-symbol / section an address-forming instruction points
        /// at). Empty in the direct-decode modes.
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

    /// Emit the full listing for a walked binary, line by line (no
    /// whole-listing accumulation). Stream-level diagnostics of each
    /// section's decode are forwarded to `onStreamDiagnostic` so the
    /// CLI can route them to stderr.
    /// Emit the full listing, optionally scoped by `addressFilter` (the
    /// `disasm --function` / `--range` window). The path header always
    /// prints; a section's header and its function labels print lazily,
    /// only once that section has an in-scope instruction, so a scope that
    /// selects nothing in a section prints no empty block for it.
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

    /// Emit one section's lines: a label line at every function start
    /// and symbol address, one instruction line per record. The section
    /// header is emitted lazily through `emitSectionHeader` (so a fully
    /// filtered-out section contributes nothing), and only in-scope
    /// instructions (and the labels sitting on them) are printed.
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
        // A section wrapping the top of the address space (hostile vmaddr)
        // holds 16-digit addresses; otherwise the width of the last one.
        let width = sectionEnd > section.address ? String(sectionEnd &- 1, radix: 16).count : 16
        let context = Context(
            section: section,
            symbols: binary.symbols,
            sections: binary.codeSections,
            stubTargets: binary.stubTargets,
            referencedData: binary.referencedDataResolver,
        )
        // The section header prints once, right before its first in-scope
        // line, so a scope that lands in no part of this section leaves it
        // out of the listing entirely.
        var headerEmitted = false
        func emitSectionHeader() {
            guard !headerEmitted else { return }
            headerEmitted = true
            emit("\n")
            emit(palette.label(section.displayName + ":") + "\n")
        }
        // The referenced-data idiom (adrp + add/ldr) reads the line before
        // the current one, so the previous record is carried forward (it is
        // tracked across filtered-out lines too, so the idiom still resolves
        // when only the completing instruction is in scope).
        var preceding: Instruction?
        for instruction in stream {
            defer { preceding = instruction }
            guard addressFilter(instruction.address) else { continue }
            emitSectionHeader()
            // Word-aligned labels only: a label can only attach to a
            // line, and lines sit at record addresses.
            if let label = labels[instruction.address] {
                emit("\n")
                emit(palette.label(label + ":") + "\n")
            }
            emit(line(for: instruction, addressWidth: width, context: context, preceding: preceding) + "\n")
        }
    }

    /// Emit a bare stream (the direct-decode modes): no labels, no
    /// symbolication context.
    public func emitStream(_ stream: InstructionStream, emit: (String) -> Void) {
        let last = stream.baseAddress &+ (stream.byteCount > 0 ? stream.byteCount &- 1 : 0)
        let width = String(last, radix: 16).count
        for instruction in stream {
            emit(line(for: instruction, addressWidth: width, context: nil, preceding: nil) + "\n")
        }
    }

    /// Render one instruction line (no trailing newline). `preceding` is
    /// the instruction before this one in the stream (the local idiom's
    /// first half), `nil` at a section's start and in the direct-decode
    /// modes.
    public func line(
        for instruction: Instruction,
        addressWidth: Int,
        context: Context?,
        preceding: Instruction? = nil,
    ) -> String {
        let address = InstructionText.address(instruction.address, width: addressWidth)
        let word = wordColumn(for: instruction)
        var body = bodyText(for: instruction, context: context, preceding: preceding)

        if includeSemantics {
            let annotation = SemanticsAnnotation.annotation(for: instruction)
            if !annotation.isEmpty {
                let padding = String(repeating: " ", count: max(Self.semanticsColumn - body.plain.count, 1))
                body.colored += padding + palette.annotation("; " + annotation)
            }
        }
        return palette.address(address + ":") + " " + word + "  " + body.colored
    }

    /// The 8-character raw-word column; truncated tails show their
    /// residual bytes' value at its natural width, space-padded.
    func wordColumn(for instruction: Instruction) -> String {
        let tailBytes = instruction.record.tailByteCount
        if tailBytes > 0 {
            let digits = tailBytes * 2
            let s = String(instruction.encoding, radix: 16)
            let padded = String(repeating: "0", count: max(digits - s.count, 0)) + s
            return padded + String(repeating: " ", count: 8 - digits)
        }
        return InstructionText.word(instruction.encoding)
    }

    /// The text column: canonical text with branch targets made
    /// absolute, plus symbolication / data-in-code annotation. Returned
    /// in plain and colored forms so callers can pad on plain text.
    func bodyText(
        for instruction: Instruction,
        context: Context?,
        preceding: Instruction? = nil,
    ) -> (plain: String, colored: String) {
        switch instruction.category {
        case .dataInCodeMarker:
            let kindSuffix = dataInCodeKindName(for: instruction, in: context?.section)
                .map { " ; data-in-code (\($0))" } ?? ""
            return (
                instruction.text + kindSuffix,
                palette.data(instruction.text) + palette.annotation(kindSuffix),
            )
        case .undefined:
            // Without the note, an UNDEFINED `.long` is indistinguishable
            // from a data-in-code `.long` at a glance.
            return (
                instruction.text + " ; undefined",
                palette.data(instruction.text) + palette.annotation(" ; undefined"),
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

    /// The trailing comment for a non-sentinel line, in priority order:
    /// branch-target symbolication when the record branches; the
    /// referenced datum (a quoted string, a data symbol, or a section
    /// name) an address-forming instruction points at, including the
    /// local `adrp`+`add`/`ldr` idiom completed with `preceding`; the
    /// formed absolute PC-relative address (a bare `adrp` page, or a
    /// target in no data section) so the page/offset math still shows;
    /// then a printable-ASCII character hint for an immediate.
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

    /// The trailing-comment text for a resolved ``ReferencedData``: the
    /// quoted string when one was read, else the data symbol when one
    /// names the target, else the bare section name. String wins because
    /// it is the most specific (the actual bytes), symbol next, section
    /// last, the same specificity order `otool` annotates with.
    func referencedDataComment(_ data: ReferencedData) -> String {
        if let string = data.string {
            return InstructionText.quotedString(string)
        }
        if let symbol = data.symbol {
            return symbol
        }
        return data.section
    }

    /// The data-in-code kind covering this word, rendered in the
    /// listing's fixed vocabulary.
    func dataInCodeKindName(for instruction: Instruction, in section: CodeSection?) -> String? {
        guard let section else { return nil }
        let offset = instruction.address &- section.address
        let span = section.dataInCode.first { offset >= $0.offset && offset < $0.offset &+ $0.length }
        return span.map { kindName($0.kind) }
    }

    /// Fixed vocabulary for ``DataInCodeSpan/Kind`` in annotations.
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

    /// Branch-target symbolication: a stub forwarding to an import
    /// (`symbol stub for: _name`) takes precedence; otherwise the symbol
    /// exactly at the target, or the closest preceding symbol as
    /// `name+0x<delta>`, the latter only when target and symbol lie in
    /// the same code section (cross-section deltas would fabricate
    /// locality).
    func symbolAnnotation(for instruction: Instruction, context: Context?) -> String? {
        guard let context, let target = instruction.branchTarget else { return nil }
        guard let resolution = context.symbolizer.resolve(target: target) else { return nil }
        return resolution.isStub ? "symbol stub for: " + resolution.name : resolution.name
    }

    /// All symbols inside the section's address range, split into two
    /// queries when the range wraps the top of the address space
    /// (`Range` cannot express the wrap, and a hostile vmaddr must not
    /// crash the listing).
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

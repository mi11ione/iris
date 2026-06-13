// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// Hand-rolled JSON emission: a third-party encoder is out (zero
// dependencies) and Foundation's JSONSerialization does not guarantee
// key order, which the NDJSON goldens and the documented schema do.
// Schema: the JSONOutput DocC article in Sources/Iris/Iris.docc
// (schemaVersion 1).

import Iris

/// Deterministic JSON fragments for the `--json` NDJSON stream.
public enum JSONText {
    /// The `schemaVersion` value emitted on every line.
    public static let schemaVersion = 1

    /// Per-binary symbol context for file-mode NDJSON: the containing
    /// function of each record and the resolved name of its branch target.
    /// Absent in the direct-decode modes (raw bytes carry no symbols), so
    /// those streams emit no `symbol` / `targetSymbol` field.
    @frozen
    public struct SymbolContext: Sendable {
        /// Function boundaries, for the `symbol` (containing function) field.
        public let labels: FunctionLabels
        /// Branch-target resolver, for the `targetSymbol` field.
        public let symbolizer: BranchSymbolizer
        /// Referenced-data resolver, for the `referencedSection` /
        /// `referencedString` / `referencedSymbol` fields.
        public let referencedData: ReferencedDataResolver

        @inlinable
        public init(
            labels: FunctionLabels,
            symbolizer: BranchSymbolizer,
            referencedData: ReferencedDataResolver = .empty,
        ) {
            self.labels = labels
            self.symbolizer = symbolizer
            self.referencedData = referencedData
        }

        /// Build the context straight from a walked binary.
        @inlinable
        public init(binary: WalkedBinary) {
            labels = FunctionLabels(functionStarts: binary.functionStarts, symbols: binary.symbols)
            symbolizer = BranchSymbolizer(
                symbols: binary.symbols,
                sections: binary.codeSections,
                stubTargets: binary.stubTargets,
            )
            referencedData = binary.referencedDataResolver
        }
    }

    /// JSON string literal with the mandatory escapes (quote, backslash,
    /// control characters; the two-character forms where JSON names them).
    public static func string(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case let s where s.value < 0x20:
                let hex = String(s.value, radix: 16)
                out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default:
                out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    /// JSON array of strings.
    public static func array(_ values: [String]) -> String {
        "[" + values.map(string).joined(separator: ",") + "]"
    }

    /// One NDJSON instruction object. Field order is fixed by the schema:
    /// `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`,
    /// `text`, `category`, `operands`, `reads`, `writes`, `branchClass`,
    /// `memoryAccess`, `ordering`, `flagEffect`, then the optional
    /// `branchTarget` / `pcRelativeTarget` / `symbol` / `targetSymbol`,
    /// then `isData`, `isUndefined`.
    ///
    /// In file mode, `context` supplies the containing-function `symbol`
    /// and the resolved `targetSymbol`; the direct-decode modes pass `nil`
    /// (raw bytes carry no symbols) and emit neither field. All additions
    /// are optional, so `schemaVersion` stays `1` per the schema's
    /// add-only policy.
    ///
    /// `includeSchemaVersion` defaults to `true` (the standalone
    /// per-instruction stream). The `functions` verb's wrapper sets it
    /// `false` so the nested instruction object drops the redundant leading
    /// `schemaVersion` the enclosing function object already carries;
    /// every other field stays identical, so a nested object plucked out
    /// is a valid instruction record but for that one owner-supplied key.
    public static func instructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        includeSchemaVersion: Bool = true,
        preceding: Instruction? = nil,
    ) -> String {
        var fields: [String] = []
        if includeSchemaVersion {
            fields.append("\"schemaVersion\":\(schemaVersion)")
        }
        fields.append("\"kind\":\"instruction\"")
        fields.append("\"address\":\(string(InstructionText.hex(instruction.address)))")
        fields.append("\"encoding\":\(string("0x" + InstructionText.word(instruction.encoding)))")
        fields.append("\"mnemonic\":\(string(instruction.mnemonic.name))")
        fields.append("\"text\":\(string(instruction.text))")
        fields.append("\"category\":\(string(categoryName(instruction.category)))")
        let operands = isSentinel(instruction.category) ? [] : InstructionText.operandFragments(of: instruction.text)
        fields.append("\"operands\":\(array(operands))")
        fields.append("\"reads\":\(array(instruction.semanticReads.map(\.name)))")
        fields.append("\"writes\":\(array(instruction.semanticWrites.map(\.name)))")
        fields.append("\"branchClass\":\(string(SemanticsAnnotation.branchName(instruction.branchClass) ?? "none"))")
        fields.append("\"memoryAccess\":\(string(SemanticsAnnotation.memoryName(instruction.memoryAccess) ?? "none"))")
        fields.append("\"ordering\":\(array(orderingNames(instruction.memoryOrdering)))")
        let readLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.readFlags, reading: true)
        let writeLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.writtenFlags, reading: false)
        fields.append("\"flagEffect\":{\"reads\":\(string(readLetters)),\"writes\":\(string(writeLetters))}")
        if let target = instruction.branchTarget {
            fields.append("\"branchTarget\":\(string(InstructionText.hex(target)))")
        }
        if let target = instruction.pcRelativeTarget {
            fields.append("\"pcRelativeTarget\":\(string(InstructionText.hex(target)))")
        }
        if let context, let symbol = context.labels.containing(instruction.address) {
            fields.append("\"symbol\":\(string(symbol))")
        }
        if let context, let target = instruction.branchTarget,
           let resolution = context.symbolizer.resolve(target: target)
        {
            fields.append("\"targetSymbol\":\(string(resolution.name))")
        }
        // Referenced-data fields: the section / string / data-symbol an
        // address-forming instruction points at (the listing's `; "str"`
        // / `; _sym` / `; __const` comment). Each present only when
        // resolved, so a consumer of the original schema is unaffected.
        if let context, let data = context.referencedData.resolve(instruction, preceding: preceding) {
            fields.append("\"referencedSection\":\(string(data.section))")
            if let referencedString = data.string {
                fields.append("\"referencedString\":\(string(referencedString))")
            }
            if let referencedSymbol = data.symbol {
                fields.append("\"referencedSymbol\":\(string(referencedSymbol))")
            }
        }
        // The printable-ASCII character an immediate names (`cmp w0, #65`
        // → `"A"`), present only when one applies.
        if let character = CharLiteralHint.character(for: instruction) {
            fields.append("\"charLiteral\":\(string(String(character)))")
        }
        fields.append("\"isData\":\(instruction.category == .dataInCodeMarker)")
        fields.append("\"isUndefined\":\(instruction.isUndefined)")
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// One NDJSON `kind:"function"` object for `functions --json`. Field
    /// order is fixed: `schemaVersion`, `kind`, `symbol`, `address`,
    /// `endAddress`, `instructionCount`, `usesPAC`, `instructions`. The
    /// function object owns the `schemaVersion`, so each nested instruction
    /// object is the per-instruction record with its redundant leading
    /// `schemaVersion` omitted and every other field identical (including
    /// the same `context`-supplied `symbol` / `targetSymbol`). `usesPAC`
    /// mirrors the human table's PAC column: true when any instruction in
    /// the function uses pointer authentication.
    public static func functionLine(
        _ function: FunctionView,
        context: SymbolContext? = nil,
    ) -> String {
        var fields: [String] = []
        fields.append("\"schemaVersion\":\(schemaVersion)")
        fields.append("\"kind\":\"function\"")
        fields.append("\"symbol\":\(string(function.symbol))")
        fields.append("\"address\":\(string(InstructionText.hex(function.address)))")
        fields.append("\"endAddress\":\(string(InstructionText.hex(function.endAddress)))")
        fields.append("\"instructionCount\":\(function.instructionCount)")
        fields.append("\"usesPAC\":\(function.usesPointerAuthentication)")
        // Thread each instruction's predecessor so the referenced-data
        // idiom (adrp + add/ldr) resolves inside the function exactly as it
        // does in the per-instruction stream.
        var nestedLines: [String] = []
        nestedLines.reserveCapacity(function.instructions.count)
        var preceding: Instruction?
        for instruction in function.instructions {
            nestedLines.append(instructionLine(
                instruction, context: context, includeSchemaVersion: false, preceding: preceding,
            ))
            preceding = instruction
        }
        let nested = nestedLines.joined(separator: ",")
        fields.append("\"instructions\":[\(nested)]")
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// One `--slim` NDJSON instruction object: the same data as
    /// ``instructionLine(_:context:includeSchemaVersion:preceding:)`` with
    /// the zero-signal constants dropped. `kind` and `schemaVersion` are
    /// gone, and a field that is empty or false is omitted entirely:
    /// `ordering` when relaxed, `flagEffect` when no flags move, `isData`
    /// and `isUndefined` when false. Every signal-bearing field survives
    /// in the same fixed order, so a kept field's position never shifts.
    ///
    /// `dropSymbol` removes the per-instruction `symbol` (the
    /// `functions --json --slim` case names the function on the parent
    /// object, so repeating it per line is pure boilerplate); the
    /// per-instruction stream keeps it.
    public static func slimInstructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        preceding: Instruction? = nil,
        dropSymbol: Bool = false,
    ) -> String {
        var fields: [String] = []
        fields.append("\"address\":\(string(InstructionText.hex(instruction.address)))")
        fields.append("\"encoding\":\(string("0x" + InstructionText.word(instruction.encoding)))")
        fields.append("\"mnemonic\":\(string(instruction.mnemonic.name))")
        fields.append("\"text\":\(string(instruction.text))")
        fields.append("\"category\":\(string(categoryName(instruction.category)))")
        let operands = isSentinel(instruction.category) ? [] : InstructionText.operandFragments(of: instruction.text)
        fields.append("\"operands\":\(array(operands))")
        fields.append("\"reads\":\(array(instruction.semanticReads.map(\.name)))")
        fields.append("\"writes\":\(array(instruction.semanticWrites.map(\.name)))")
        // branchClass / memoryAccess only when not "none" (the no-effect
        // baseline carries no signal).
        if let branch = SemanticsAnnotation.branchName(instruction.branchClass) {
            fields.append("\"branchClass\":\(string(branch))")
        }
        if let memory = SemanticsAnnotation.memoryName(instruction.memoryAccess) {
            fields.append("\"memoryAccess\":\(string(memory))")
        }
        let orderingList = orderingNames(instruction.memoryOrdering)
        if !orderingList.isEmpty {
            fields.append("\"ordering\":\(array(orderingList))")
        }
        let readLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.readFlags, reading: true)
        let writeLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.writtenFlags, reading: false)
        if !readLetters.isEmpty || !writeLetters.isEmpty {
            fields.append("\"flagEffect\":{\"reads\":\(string(readLetters)),\"writes\":\(string(writeLetters))}")
        }
        if let target = instruction.branchTarget {
            fields.append("\"branchTarget\":\(string(InstructionText.hex(target)))")
        }
        if let target = instruction.pcRelativeTarget {
            fields.append("\"pcRelativeTarget\":\(string(InstructionText.hex(target)))")
        }
        if !dropSymbol, let context, let symbol = context.labels.containing(instruction.address) {
            fields.append("\"symbol\":\(string(symbol))")
        }
        if let context, let target = instruction.branchTarget,
           let resolution = context.symbolizer.resolve(target: target)
        {
            fields.append("\"targetSymbol\":\(string(resolution.name))")
        }
        if let context, let data = context.referencedData.resolve(instruction, preceding: preceding) {
            fields.append("\"referencedSection\":\(string(data.section))")
            if let referencedString = data.string {
                fields.append("\"referencedString\":\(string(referencedString))")
            }
            if let referencedSymbol = data.symbol {
                fields.append("\"referencedSymbol\":\(string(referencedSymbol))")
            }
        }
        if let character = CharLiteralHint.character(for: instruction) {
            fields.append("\"charLiteral\":\(string(String(character)))")
        }
        // isData / isUndefined only when true (the witness is the presence
        // of the field; false is the silent default).
        if instruction.category == .dataInCodeMarker {
            fields.append("\"isData\":true")
        }
        if instruction.isUndefined {
            fields.append("\"isUndefined\":true")
        }
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// One `--slim` NDJSON function object for
    /// `functions --json --slim`. Same naming fields as
    /// ``functionLine(_:context:)`` (`symbol` / `address` / `endAddress` /
    /// `instructionCount`, all signal) with the constant `kind` and
    /// `schemaVersion` dropped; the object is unmistakably a function (it
    /// is the only shape carrying `instructions`). `usesPAC` follows the
    /// slim drop-false rule: it appears only when the function uses pointer
    /// authentication, so a present `usesPAC` always means true. The nested
    /// instructions are the slim projection with the redundant
    /// per-instruction `symbol` dropped (the parent object already names
    /// the function).
    public static func slimFunctionLine(
        _ function: FunctionView,
        context: SymbolContext? = nil,
    ) -> String {
        var fields: [String] = []
        fields.append("\"symbol\":\(string(function.symbol))")
        fields.append("\"address\":\(string(InstructionText.hex(function.address)))")
        fields.append("\"endAddress\":\(string(InstructionText.hex(function.endAddress)))")
        fields.append("\"instructionCount\":\(function.instructionCount)")
        if function.usesPointerAuthentication {
            fields.append("\"usesPAC\":true")
        }
        var nestedLines: [String] = []
        nestedLines.reserveCapacity(function.instructions.count)
        var preceding: Instruction?
        for instruction in function.instructions {
            nestedLines.append(slimInstructionLine(
                instruction, context: context, preceding: preceding, dropSymbol: true,
            ))
            preceding = instruction
        }
        fields.append("\"instructions\":[\(nestedLines.joined(separator: ","))]")
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// Whether a category is a decoder sentinel (its text is a directive,
    /// not mnemonic + operands, no operand fragments exist).
    static func isSentinel(_ category: Category) -> Bool {
        category == .undefined || category == .dataInCodeMarker || category == .truncatedTail
    }

    /// `["acquire"]`, `["release"]`, or both, matching the annotation
    /// vocabulary.
    static func orderingNames(_ ordering: MemoryOrdering) -> [String] {
        var names: [String] = []
        if ordering.contains(.acquire) { names.append("acquire") }
        if ordering.contains(.release) { names.append("release") }
        return names
    }

    /// Stable category names (the `Category` case names).
    public static func categoryName(_ category: Category) -> String {
        switch category {
        case .undefined: "undefined"
        case .dataInCodeMarker: "dataInCodeMarker"
        case .truncatedTail: "truncatedTail"
        case .dataProcessingImmediate: "dataProcessingImmediate"
        case .branchesExceptionSystem: "branchesExceptionSystem"
        case .dataProcessingRegister: "dataProcessingRegister"
        case .loadsAndStores: "loadsAndStores"
        case .simdAndFP: "simdAndFP"
        case .pointerAuthentication: "pointerAuthentication"
        case .crypto: "crypto"
        case .amx: "amx"
        case .memoryTagging: "memoryTagging"
        }
    }
}

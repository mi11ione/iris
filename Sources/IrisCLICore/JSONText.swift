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

        @inlinable
        public init(labels: FunctionLabels, symbolizer: BranchSymbolizer) {
            self.labels = labels
            self.symbolizer = symbolizer
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
        fields.append("\"isData\":\(instruction.category == .dataInCodeMarker)")
        fields.append("\"isUndefined\":\(instruction.isUndefined)")
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// One NDJSON `kind:"function"` object for `functions --json`. Field
    /// order is fixed: `schemaVersion`, `kind`, `symbol`, `address`,
    /// `endAddress`, `instructionCount`, `instructions`. The function
    /// object owns the `schemaVersion`, so each nested instruction object
    /// is the per-instruction record with its redundant leading
    /// `schemaVersion` omitted and every other field identical (including
    /// the same `context`-supplied `symbol` / `targetSymbol`).
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
        let nested = function.instructions
            .map { instructionLine($0, context: context, includeSchemaVersion: false) }
            .joined(separator: ",")
        fields.append("\"instructions\":[\(nested)]")
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// Whether a category is a decoder sentinel (its text is a directive,
    /// not mnemonic + operands — no operand fragments exist).
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

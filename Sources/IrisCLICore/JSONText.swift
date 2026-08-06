// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// Deterministic JSON fragments for the `--json` NDJSON stream.
public enum JSONText {
    /// The `schemaVersion` value emitted on every line.
    public static let schemaVersion = 1

    /// Per-binary symbol context for file-mode NDJSON.
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

    /// The scalable-state object for one `ScalableRegisterSet`, or `nil` when
    /// empty, in which case the field is omitted.
    public static func scalableSet(_ set: ScalableRegisterSet) -> String? {
        guard !set.isEmpty else { return nil }
        var members: [String] = []
        let predicates = set.predicateMask
        if predicates != 0 {
            let names = (0 ..< 16).filter { predicates & (UInt16(1) << $0) != 0 }.map { "p\($0)" }
            members.append("\"predicates\":\(array(names))")
        }
        let za = set.zaMask
        if !za.isEmpty {
            let hex = String(za.bits, radix: 16)
            members.append("\"za\":\(string("0x" + String(repeating: "0", count: 4 - hex.count) + hex))")
        }
        if set.containsFFR {
            members.append("\"ffr\":true")
        }
        if set.containsZT0 {
            members.append("\"zt0\":true")
        }
        return "{" + members.joined(separator: ",") + "}"
    }

    /// `ScalableEffect` flag names, in bit order.
    public static func scalableEffectNames(_ effect: ScalableEffect) -> [String] {
        var names: [String] = []
        if effect.contains(.partialWrite) { names.append("partial-write") }
        if effect.contains(.readsStreamingMode) { names.append("reads-streaming-mode") }
        if effect.contains(.writesStreamingMode) { names.append("writes-streaming-mode") }
        if effect.contains(.writesZAEnable) { names.append("writes-za-enable") }
        if effect.contains(.firstFaulting) { names.append("first-faulting") }
        if effect.contains(.nonFaulting) { names.append("non-faulting") }
        if effect.contains(.nonTemporal) { names.append("non-temporal") }
        return names
    }

    /// The three scalable fields, in schema order, for whichever of them carry
    /// signal.
    static func scalableFields(_ instruction: Instruction) -> [String] {
        var fields: [String] = []
        if let reads = scalableSet(instruction.scalableReads) {
            fields.append("\"scalableReads\":\(reads)")
        }
        if let writes = scalableSet(instruction.scalableWrites) {
            fields.append("\"scalableWrites\":\(writes)")
        }
        let effects = scalableEffectNames(instruction.scalableEffect)
        if !effects.isEmpty {
            fields.append("\"scalableEffect\":\(array(effects))")
        }
        return fields
    }

    /// One NDJSON instruction object, in fixed schema order.
    public static func instructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        includeSchemaVersion: Bool = true,
        preceding: Instruction? = nil,
    ) -> String {
        var out = TextBytes(capacity: 512)
        putInstructionLine(
            instruction, context: context,
            includeSchemaVersion: includeSchemaVersion, preceding: preceding, into: &out,
        )
        return out.makeString()
    }

    /// One NDJSON `kind:"function"` object, in fixed order.
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

    /// One `--slim` instruction object.
    public static func slimInstructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        preceding: Instruction? = nil,
        dropSymbol: Bool = false,
    ) -> String {
        var out = TextBytes(capacity: 512)
        putSlimInstructionLine(
            instruction, context: context, preceding: preceding,
            dropSymbol: dropSymbol, into: &out,
        )
        return out.makeString()
    }

    /// One `--slim` function object.
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

    /// Whether a category is a decoder sentinel (its text is a directive, not
    /// mnemonic + operands, no operand fragments exist).
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
        case .sve: "sve"
        case .sme: "sme"
        }
    }
}

public extension JSONText {
    /// A JSON string literal with the mandatory escapes, appended.
    static func putString(_ value: String, into out: inout TextBytes) {
        out.put(UInt8(ascii: "\""))
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out.put("\\\"")
            case "\\": out.put("\\\\")
            case "\n": out.put("\\n")
            case "\r": out.put("\\r")
            case "\t": out.put("\\t")
            case let s where s.value < 0x20:
                out.put("\\u")
                let hex = String(s.value, radix: 16)
                for _ in 0 ..< (4 - hex.count) {
                    out.put(UInt8(ascii: "0"))
                }
                out.putString(hex)
            case let s where s.isASCII:
                out.put(UInt8(s.value))
            default:
                out.putString(String(scalar))
            }
        }
        out.put(UInt8(ascii: "\""))
    }

    /// A JSON array of strings, appended.
    static func putArray(_ values: [String], into out: inout TextBytes) {
        out.put(UInt8(ascii: "["))
        for (i, v) in values.enumerated() {
            if i > 0 { out.put(UInt8(ascii: ",")) }
            putString(v, into: &out)
        }
        out.put(UInt8(ascii: "]"))
    }

    /// `"0x<hex>"` — the form every address-valued field uses.
    @inline(__always)
    static func putHexString(_ value: UInt64, into out: inout TextBytes) {
        out.put("\"0x")
        out.putHex(value)
        out.put(UInt8(ascii: "\""))
    }

    /// The per-instruction record, appended.
    static func putInstructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        includeSchemaVersion: Bool = true,
        preceding: Instruction? = nil,
        into out: inout TextBytes,
    ) {
        out.put(UInt8(ascii: "{"))
        if includeSchemaVersion {
            out.put("\"schemaVersion\":")
            out.putDecimal(UInt64(schemaVersion))
            out.put(UInt8(ascii: ","))
        }
        out.put("\"kind\":\"instruction\",\"address\":")
        putHexString(instruction.address, into: &out)
        out.put(",\"encoding\":\"0x")
        InstructionText.putWord(instruction.encoding, into: &out)
        out.put("\",\"mnemonic\":")
        putString(instruction.mnemonic.name, into: &out)
        out.put(",\"text\":")
        putString(instruction.text, into: &out)
        out.put(",\"category\":")
        putString(categoryName(instruction.category), into: &out)
        out.put(",\"operands\":")
        putArray(isSentinel(instruction.category)
            ? [] : InstructionText.operandFragments(of: instruction.text), into: &out)
        out.put(",\"reads\":")
        putArray(instruction.semanticReads.map(\.name), into: &out)
        out.put(",\"writes\":")
        putArray(instruction.semanticWrites.map(\.name), into: &out)
        out.put(",\"branchClass\":")
        putString(SemanticsAnnotation.branchName(instruction.branchClass) ?? "none", into: &out)
        out.put(",\"memoryAccess\":")
        putString(SemanticsAnnotation.memoryName(instruction.memoryAccess) ?? "none", into: &out)
        out.put(",\"ordering\":")
        putArray(orderingNames(instruction.memoryOrdering), into: &out)
        out.put(",\"flagEffect\":{\"reads\":")
        putString(
            SemanticsAnnotation.flagLetters(instruction.flagEffect.readFlags, reading: true),
            into: &out,
        )
        out.put(",\"writes\":")
        putString(
            SemanticsAnnotation.flagLetters(instruction.flagEffect.writtenFlags, reading: false),
            into: &out,
        )
        out.put(UInt8(ascii: "}"))
        for field in scalableFields(instruction) {
            out.put(UInt8(ascii: ","))
            out.putString(field)
        }
        if let target = instruction.branchTarget {
            out.put(",\"branchTarget\":")
            putHexString(target, into: &out)
        }
        if let target = instruction.pcRelativeTarget {
            out.put(",\"pcRelativeTarget\":")
            putHexString(target, into: &out)
        }
        if let context, let symbol = context.labels.containing(instruction.address) {
            out.put(",\"symbol\":")
            putString(symbol, into: &out)
        }
        if let context, let target = instruction.branchTarget,
           let resolution = context.symbolizer.resolve(target: target)
        {
            out.put(",\"targetSymbol\":")
            putString(resolution.name, into: &out)
        }
        if let context, let data = context.referencedData.resolve(instruction, preceding: preceding) {
            out.put(",\"referencedSection\":")
            putString(data.section, into: &out)
            if let referencedString = data.string {
                out.put(",\"referencedString\":")
                putString(referencedString, into: &out)
            }
            if let referencedSymbol = data.symbol {
                out.put(",\"referencedSymbol\":")
                putString(referencedSymbol, into: &out)
            }
        }
        if let character = CharLiteralHint.character(for: instruction) {
            out.put(",\"charLiteral\":")
            putString(String(character), into: &out)
        }
        out.put(",\"isData\":")
        out.put(instruction.category == .dataInCodeMarker ? "true" : "false")
        out.put(",\"isUndefined\":")
        out.put(instruction.isUndefined ? "true" : "false")
        out.put(UInt8(ascii: "}"))
    }
}

public extension JSONText {
    /// The slim per-instruction record, appended.
    static func putSlimInstructionLine(
        _ instruction: Instruction,
        context: SymbolContext? = nil,
        preceding: Instruction? = nil,
        dropSymbol: Bool = false,
        into out: inout TextBytes,
    ) {
        out.put("{\"address\":")
        putHexString(instruction.address, into: &out)
        out.put(",\"encoding\":\"0x")
        InstructionText.putWord(instruction.encoding, into: &out)
        out.put("\",\"mnemonic\":")
        putString(instruction.mnemonic.name, into: &out)
        out.put(",\"text\":")
        putString(instruction.text, into: &out)
        out.put(",\"category\":")
        putString(categoryName(instruction.category), into: &out)
        out.put(",\"operands\":")
        putArray(isSentinel(instruction.category)
            ? [] : InstructionText.operandFragments(of: instruction.text), into: &out)
        out.put(",\"reads\":")
        putArray(instruction.semanticReads.map(\.name), into: &out)
        out.put(",\"writes\":")
        putArray(instruction.semanticWrites.map(\.name), into: &out)
        if let branch = SemanticsAnnotation.branchName(instruction.branchClass) {
            out.put(",\"branchClass\":")
            putString(branch, into: &out)
        }
        if let memory = SemanticsAnnotation.memoryName(instruction.memoryAccess) {
            out.put(",\"memoryAccess\":")
            putString(memory, into: &out)
        }
        let orderingList = orderingNames(instruction.memoryOrdering)
        if !orderingList.isEmpty {
            out.put(",\"ordering\":")
            putArray(orderingList, into: &out)
        }
        let readLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.readFlags, reading: true)
        let writeLetters = SemanticsAnnotation.flagLetters(instruction.flagEffect.writtenFlags, reading: false)
        if !readLetters.isEmpty || !writeLetters.isEmpty {
            out.put(",\"flagEffect\":{\"reads\":")
            putString(readLetters, into: &out)
            out.put(",\"writes\":")
            putString(writeLetters, into: &out)
            out.put(UInt8(ascii: "}"))
        }
        for field in scalableFields(instruction) {
            out.put(UInt8(ascii: ","))
            out.putString(field)
        }
        if let target = instruction.branchTarget {
            out.put(",\"branchTarget\":")
            putHexString(target, into: &out)
        }
        if let target = instruction.pcRelativeTarget {
            out.put(",\"pcRelativeTarget\":")
            putHexString(target, into: &out)
        }
        if !dropSymbol, let context, let symbol = context.labels.containing(instruction.address) {
            out.put(",\"symbol\":")
            putString(symbol, into: &out)
        }
        if let context, let target = instruction.branchTarget,
           let resolution = context.symbolizer.resolve(target: target)
        {
            out.put(",\"targetSymbol\":")
            putString(resolution.name, into: &out)
        }
        if let context, let data = context.referencedData.resolve(instruction, preceding: preceding) {
            out.put(",\"referencedSection\":")
            putString(data.section, into: &out)
            if let referencedString = data.string {
                out.put(",\"referencedString\":")
                putString(referencedString, into: &out)
            }
            if let referencedSymbol = data.symbol {
                out.put(",\"referencedSymbol\":")
                putString(referencedSymbol, into: &out)
            }
        }
        if let character = CharLiteralHint.character(for: instruction) {
            out.put(",\"charLiteral\":")
            putString(String(character), into: &out)
        }
        if instruction.category == .dataInCodeMarker { out.put(",\"isData\":true") }
        if instruction.isUndefined { out.put(",\"isUndefined\":true") }
        out.put(UInt8(ascii: "}"))
    }
}

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

    /// The scalable-state object for one `ScalableRegisterSet`, or `nil`
    /// when the set is empty (the field is then omitted entirely).
    ///
    /// Only the non-empty members appear, so a scalable line stays close to
    /// the `--semantics` text and a base-ISA line carries nothing at all.
    /// `za` is the 16-bit `.Q`-position residue mask as `0x` + 4 hex digits,
    /// not a tile name: many tile/element pairs share a mask and unions have
    /// no single name, so the mask is the only faithful rendering.
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

    /// `ScalableEffect` flag names, in bit order. Empty for `none`.
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

    /// The three scalable fields, in schema order, for whichever of them
    /// carry signal. Shared by the default and slim emitters: these fields
    /// are absent-when-empty in both, so scalable state costs a base-ISA
    /// line nothing.
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

    /// One NDJSON instruction object. Field order is fixed by the schema:
    /// `schemaVersion`, `kind`, `address`, `encoding`, `mnemonic`,
    /// `text`, `category`, `operands`, `reads`, `writes`, `branchClass`,
    /// `memoryAccess`, `ordering`, `flagEffect`, then the optional
    /// `scalableReads` / `scalableWrites` / `scalableEffect` (scalable
    /// records only), `branchTarget` / `pcRelativeTarget` / `symbol` /
    /// `targetSymbol`, then `isData`, `isUndefined`.
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
        var out = TextBytes(capacity: 512)
        putInstructionLine(
            instruction, context: context,
            includeSchemaVersion: includeSchemaVersion, preceding: preceding, into: &out,
        )
        return out.makeString()
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
    /// The scalable fields are already absent-when-empty in the default
    /// form, so slim carries them unchanged.
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
        var out = TextBytes(capacity: 512)
        putSlimInstructionLine(
            instruction, context: context, preceding: preceding,
            dropSymbol: dropSymbol, into: &out,
        )
        return out.makeString()
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
        case .sve: "sve"
        case .sme: "sme"
        }
    }
}

// MARK: - Byte-path JSON

// The builders above assemble a `[String]` of fields and join it: roughly
// twenty allocations per instruction, plus the array, plus the join, plus
// the line. Over a large binary that is millions of short-lived `String`s,
// and it made `--json` the slowest thing the CLI does — over three times
// the cost of the human listing it derives from.
//
// These append the same bytes into a caller-owned buffer. The
// `String`-returning entry points remain, implemented on top, so the
// published surface and every existing caller are unchanged.

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

    /// The per-instruction record, appended. Field order is the schema's.
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
    /// The slim per-instruction record, appended. Optional fields appear
    /// only when they carry signal, so the separator is tracked rather
    /// than assumed.
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
        // branchClass / memoryAccess only when not "none" (the no-effect
        // baseline carries no signal).
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
        // isData / isUndefined only when true (the witness is the presence
        // of the field; false is the silent default).
        if instruction.category == .dataInCodeMarker { out.put(",\"isData\":true") }
        if instruction.isUndefined { out.put(",\"isUndefined\":true") }
        out.put(UInt8(ascii: "}"))
    }
}

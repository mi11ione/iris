// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `functions` verb: the function-carving boundaries (loader data
/// only, with the adjacent-`__stubs` exclusion the section clamp gives),
/// the human-mode per-function summary, and the `kind:"function"` NDJSON
/// object against its documented shape and locked goldens. Every JSON line
/// parses, carries the function fields in fixed order, and wraps nested
/// instruction objects that are the per-instruction record minus the
/// redundant leading `schemaVersion`.
@Suite("Functions mode")
struct FunctionViewTests {
    /// Parse one NDJSON line into a JSON object.
    func object(_ line: some StringProtocol) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

    // MARK: Human-mode goldens

    func expectHumanGolden(fixture: String, goldenName: String) {
        let run = runCLI(["functions", "--color", "never", cliFixturePath(fixture)])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stderr.isEmpty)
        #expect(normalizedToGolden(run.stdout) == golden(goldenName))
    }

    @Test func thinSummaryMatchesGolden() {
        expectHumanGolden(fixture: "hello-arm64", goldenName: "hello-arm64.functions.txt")
    }

    @Test func arm64eSummaryMatchesGolden() {
        expectHumanGolden(fixture: "hello-arm64e", goldenName: "hello-arm64e.functions.txt")
    }

    @Test func strippedSummaryMatchesGolden() {
        expectHumanGolden(fixture: "hello-stripped", goldenName: "hello-stripped.functions.txt")
    }

    @Test func stubSummaryMatchesGolden() {
        expectHumanGolden(fixture: "stub-arm64", goldenName: "stub-arm64.functions.txt")
    }

    // MARK: JSON-mode goldens

    @Test func thinJSONMatchesGolden() {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("hello-arm64.functions.ndjson"))
    }

    @Test func arm64eJSONMatchesGolden() {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64e")])
        #expect(run.stdout == golden("hello-arm64e.functions.ndjson"))
    }

    @Test func stubJSONMatchesGolden() {
        let run = runCLI(["functions", "--json", cliFixturePath("stub-arm64")])
        #expect(run.stdout == golden("stub-arm64.functions.ndjson"))
    }

    // MARK: JSON object shape

    static let functionFields = ["schemaVersion", "kind", "symbol", "address", "endAddress", "instructionCount", "instructions"]

    @Test func everyFunctionObjectHasTheFixedShape() throws {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let lines = run.stdout.split(separator: "\n")
        #expect(lines.count == 4)
        for line in lines {
            let fields = try #require(object(line), "unparseable function line: \(line)")
            for required in Self.functionFields {
                #expect(fields[required] != nil, "missing \(required) in: \(line)")
            }
            #expect(fields["schemaVersion"] as? Int == JSONText.schemaVersion)
            #expect(fields["kind"] as? String == "function")
            #expect((fields["symbol"] as? String)?.isEmpty == false)
            let address = try #require(fields["address"] as? String)
            #expect(address.hasPrefix("0x"))
            let endAddress = try #require(fields["endAddress"] as? String)
            #expect(endAddress.hasPrefix("0x"))
            let count = try #require(fields["instructionCount"] as? Int)
            let instructions = try #require(fields["instructions"] as? [[String: Any]])
            #expect(instructions.count == count)
        }
    }

    @Test func functionObjectKeyOrderIsFixed() throws {
        // The hand-rolled emitter pins key order; assert it on the raw text
        // (JSONSerialization would not preserve it).
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let first = try #require(run.stdout.split(separator: "\n").first)
        let prefix = "{\"schemaVersion\":1,\"kind\":\"function\",\"symbol\":\"_add42\","
            + "\"address\":\"0x100000328\",\"endAddress\":\"0x100000340\","
            + "\"instructionCount\":6,\"instructions\":[{"
        #expect(first.hasPrefix(prefix))
    }

    @Test func addressIsFirstInstructionAndEndIsExclusive() throws {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let lines = run.stdout.split(separator: "\n")
        for line in lines {
            let fields = try #require(object(line))
            let instructions = try #require(fields["instructions"] as? [[String: Any]])
            let address = fields["address"] as? String
            // The function address equals its first instruction's address.
            #expect(address == instructions.first?["address"] as? String)
        }
        // _add42's exclusive end equals _sum_to's start (contiguous starts);
        // _main's end is the section end past its last instruction.
        let parsed = lines.compactMap { object($0) }
        let add42 = try #require(parsed.first { $0["symbol"] as? String == "_add42" })
        #expect(add42["endAddress"] as? String == "0x100000340")
        let main = try #require(parsed.first { $0["symbol"] as? String == "_main" })
        #expect(main["address"] as? String == "0x1000003d4")
        #expect(main["endAddress"] as? String == "0x100000400")
    }

    @Test func nestedInstructionObjectsAreValidRecords() throws {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let first = try #require(run.stdout.split(separator: "\n").first)
        let fields = try #require(object(first))
        let instructions = try #require(fields["instructions"] as? [[String: Any]])
        for nested in instructions {
            // The nested object drops only schemaVersion; it keeps the
            // instruction discriminator and the per-instruction fields.
            #expect(nested["schemaVersion"] == nil)
            #expect(nested["kind"] as? String == "instruction")
            #expect(nested["address"] is String)
            #expect(nested["encoding"] is String)
            #expect(nested["mnemonic"] is String)
        }
    }

    @Test func nestedObjectPlusSchemaVersionEqualsTheStandaloneLine() {
        // The contract: a nested instruction object with schemaVersion
        // reinserted is byte-identical to the default per-instruction line.
        let perInstruction = runCLI(["--json", cliFixturePath("hello-arm64")])
        let perFunction = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let standalone = perInstruction.stdout.split(separator: "\n").map(String.init)

        var reconstructed: [String] = []
        for functionLine in perFunction.stdout.split(separator: "\n") {
            for nested in nestedObjects(of: String(functionLine)) {
                #expect(nested.hasPrefix("{\"kind\":\"instruction\""))
                reconstructed.append("{\"schemaVersion\":1," + nested.dropFirst())
            }
        }
        #expect(reconstructed == standalone)
    }

    /// Split the `"instructions":[ … ]` payload of a function line into its
    /// top-level `{…}` object substrings by brace depth. The schema places
    /// no `{`/`}` inside string values, so depth tracking suffices.
    func nestedObjects(of functionLine: String) -> [String] {
        guard let keyRange = functionLine.range(of: "\"instructions\":[") else { return [] }
        var depth = 0
        var current = ""
        var objects: [String] = []
        for character in functionLine[keyRange.upperBound...] {
            if character == "{" { depth += 1 }
            if depth >= 1 { current.append(character) }
            if character == "}" {
                depth -= 1
                if depth == 0 {
                    objects.append(current)
                    current = ""
                }
            }
            if character == "]", depth == 0 { break }
        }
        return objects
    }

    @Test func nestedObjectsOfALineWithoutAnInstructionsKeyIsEmpty() {
        // The splitter keys off `"instructions":[`. A line that carries no
        // such key (an empty string, or any non-function text) yields nothing.
        #expect(nestedObjects(of: "") == [])
        #expect(nestedObjects(of: "{\"kind\":\"census\",\"totalWords\":0}") == [])
    }

    // MARK: Boundaries and the adjacent-stub exclusion

    @Test func functionStartsBecomeFunctionsInAddressOrder() {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let symbols = run.stdout.split(separator: "\n").compactMap { object($0)?["symbol"] as? String }
        #expect(symbols == ["_add42", "_sum_to", "_helper", "_main"])
    }

    @Test func adjacentStubIsExcludedFromEveryFunction() throws {
        // stub-arm64's __stubs island (0x10000042c+) sits in a different
        // section with no function start. group_by(.symbol) over the
        // per-instruction stream would attribute it to _main; the section
        // clamp must keep every function's range below the stub.
        let run = runCLI(["functions", "--json", cliFixturePath("stub-arm64")])
        let lines = run.stdout.split(separator: "\n")
        let symbols = lines.compactMap { object($0)?["symbol"] as? String }
        #expect(symbols == ["_compare", "_main"])
        for line in lines {
            let fields = try #require(object(line))
            let end = try #require(fields["endAddress"] as? String)
            // No function reaches into the __stubs section at 0x10000042c.
            let endValue = try #require(UInt64(end.dropFirst(2), radix: 16))
            #expect(endValue <= 0x1_0000_042C)
            // And no nested instruction sits at or past the stub.
            let instructions = try #require(fields["instructions"] as? [[String: Any]])
            for nested in instructions {
                let addr = try UInt64(#require((nested["address"] as? String)?.dropFirst(2)), radix: 16)!
                #expect(addr < 0x1_0000_042C)
            }
        }
    }

    @Test func strippedFunctionsUseSubLabels() {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-stripped")])
        let symbols = run.stdout.split(separator: "\n").compactMap { object($0)?["symbol"] as? String }
        #expect(symbols == ["sub_100000328", "sub_100000340", "sub_100000398", "sub_1000003d4"])
    }

    // MARK: Rollups

    @Test func summaryRollupsAreComputedFromInstructions() {
        // _helper calls _add42 and _sum_to (2 calls); _main calls _helper
        // (1 call); the arm64e build's _helper/_main carry PAC prologues.
        let plain = runCLI(["functions", "--color", "never", cliFixturePath("hello-arm64")])
        #expect(plain.stdout.contains("_helper") && plain.stdout.contains("  2  "))
        let auth = runCLI(["functions", "--color", "never", cliFixturePath("hello-arm64e")])
        // arm64e summary marks pointer authentication present for some rows.
        #expect(auth.stdout.contains("yes"))
        // and the leaf functions still report no PAC.
        #expect(auth.stdout.contains(" no"))
    }

    // MARK: Carver directly

    @Test func leadingRecordsBeforeTheFirstFunctionStartAreDropped() throws {
        // A __text at 0x1000 with four NOPs, whose only function start is
        // 0x1008 (anchored at 0x1000 + delta 0x08). The two words before
        // 0x1008 belong to no function and must not appear; the function
        // spans [0x1008, sectionEnd 0x1010), so it holds exactly two.
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD503_201F, 0xD503_201F],
            textAddr: 0x1000,
            extraSize: 16,
            extraCommands: { a in a.linkeditDataCommand(cmd: 0x26, dataoff: 280, datasize: 2) },
            trailer: { a in
                a.pad(to: 280)
                a.bytes.append(contentsOf: [0x08, 0x00]) // delta 0x08, terminator
            },
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        #expect(binary.functionStarts == [0x1008])
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.count == 1)
        let function = try #require(functions.first)
        #expect(function.address == 0x1008)
        #expect(function.endAddress == 0x1010)
        #expect(function.instructionCount == 2)
        #expect(function.instructions.map(\.address) == [0x1008, 0x100C])
        #expect(function.symbol == "sub_1008")
        // No calls, no PAC in a NOP-only function.
        #expect(function.callCount == 0)
        #expect(!function.usesPointerAuthentication)
    }

    @Test func carverUsesADefaultDiagnosticSink() throws {
        // Calling without the diagnostic argument exercises the default
        // `{ _, _ in }` sink. dic-arm64.o carries data-in-code spans, so
        // its decode surfaces stream diagnostics that the default sink
        // receives and discards (the CLI always passes its own sink; this
        // is the convenience overload a library caller uses).
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        let withSpans = binary.codeSections.contains { !$0.dataInCode.isEmpty }
        #expect(withSpans, "fixture must carry data-in-code spans to drive the default sink")
        // No function starts in the object file, so no functions are carved,
        // but the diagnostics still flow through the default sink.
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.isEmpty)
    }

    @Test func carverForwardsSectionDecodeDiagnostics() throws {
        // One sink fed two carves. The hello fixture decodes cleanly and adds
        // nothing; a section that wraps past 2^64 (with a function start
        // inside it) surfaces one address-wrap diagnostic the carver hands to
        // the same sink, section and kind in hand. Sharing the sink keeps its
        // body exercised, so the clean carve's silence is proven without a
        // callback body a well-formed binary could never reach.
        var forwarded: [(section: String, kind: Diagnostic.Kind)] = []
        let sink: (CodeSection, Diagnostic) -> Void = { section, diagnostic in
            forwarded.append((section.sectionName, diagnostic.kind))
        }

        let clean = try #require(walkedBinary(cliFixturePath("hello-arm64")))
        let cleanFunctions = FunctionCarver.functions(of: clean, onStreamDiagnostic: sink)
        #expect(cleanFunctions.map(\.symbol) == ["_add42", "_sum_to", "_helper", "_main"])
        #expect(forwarded.isEmpty)

        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: UInt64.max - 7,
            extraSize: 16,
            extraCommands: { a in a.linkeditDataCommand(cmd: 0x26, dataoff: 280, datasize: 2) },
            trailer: { a in
                a.pad(to: 280)
                a.bytes.append(contentsOf: [0x04, 0x00]) // one start at textAddr+4
            },
        )
        let wrapping = try #require(walkedBinary(bytes: bytes))
        _ = FunctionCarver.functions(of: wrapping, onStreamDiagnostic: sink)
        #expect(forwarded.contains { $0.section == "__text" })
        #expect(forwarded.contains { if case .addressSpaceWrapped = $0.kind { true } else { false } })
    }

    @Test func wrappingSectionWithoutFunctionStartsDoesNotCrash() throws {
        // A section whose addresses wrap past 2^64 and no function starts.
        // The carver's in-section filter finds nothing and returns early.
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: UInt64.max - 7,
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.isEmpty)
    }

    @Test func wrappingSectionWithAFunctionStartDoesNotCrash() throws {
        // Hostile: a section that wraps the top of the address space AND a
        // function start inside it (anchored at the section vmaddr). The
        // carve must stay total (no trap, no out-of-range) on this input.
        // Address monotonicity does not hold across the wrap, so the
        // attribution is degenerate, but totality is the contract that
        // matters for hostile input.
        let textAddr = UInt64.max - 7
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: textAddr,
            extraSize: 16,
            extraCommands: { a in a.linkeditDataCommand(cmd: 0x26, dataoff: 280, datasize: 2) },
            trailer: { a in
                a.pad(to: 280)
                // delta 0x04 then terminator: one start at textAddr+4, which
                // lands inside the wrapping section (second word's address).
                a.bytes.append(contentsOf: [0x04, 0x00])
            },
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        // Whatever the walker yields, carving it must not crash.
        let functions = FunctionCarver.functions(of: binary)
        // Total: a well-formed (possibly degenerate) result is returned.
        #expect(functions.count >= 0)
        // The CLI paths over the same binary also stay total.
        let run = withTemporaryFile(bytes: bytes) { runCLI(["functions", "--color", "never", $0]) }
        #expect(run.status == CLI.exitSuccess)
        let json = withTemporaryFile(bytes: bytes) { runCLI(["functions", "--json", $0]) }
        #expect(json.status == CLI.exitSuccess)
    }

    @Test func binaryWithoutFunctionStartsPrintsNoFunctions() {
        // dic-arm64.o has code sections but no LC_FUNCTION_STARTS.
        let human = runCLI(["functions", "--color", "never", cliFixturePath("dic-arm64.o")])
        #expect(human.status == CLI.exitSuccess)
        #expect(human.stdout.contains("(no functions)"))
        // JSON mode emits zero function objects (a valid empty NDJSON stream).
        let json = runCLI(["functions", "--json", cliFixturePath("dic-arm64.o")])
        #expect(json.status == CLI.exitSuccess)
        #expect(json.stdout.isEmpty)
    }

    // MARK: Color

    @Test func summaryColorsWhenEnabled() {
        let colored = runCLI(["functions", "--color", "always", cliFixturePath("hello-arm64")], tty: true)
        #expect(colored.stdout.contains("\u{1B}["))
        // Columns still align: stripping escapes recovers the plain golden.
        let stripped = stripANSI(colored.stdout)
        #expect(normalizedToGolden(stripped) == golden("hello-arm64.functions.txt"))
    }

    @Test func jsonModeNeverColors() {
        let run = runCLI(["functions", "--json", "--color", "always", cliFixturePath("hello-arm64")], tty: true)
        #expect(!run.stdout.contains("\u{1B}"))
    }

    /// Drop ANSI SGR escapes (`ESC [ … m`) so a colored listing can be
    /// compared to its plain golden.
    func stripANSI(_ text: String) -> String {
        var out = ""
        let scalars = Array(text.unicodeScalars)
        var i = 0
        while i < scalars.count {
            if scalars[i] == "\u{1B}", i + 1 < scalars.count, scalars[i + 1] == "[" {
                i += 2
                while i < scalars.count, scalars[i] != "m" {
                    i += 1
                }
                if i < scalars.count { i += 1 } // consume the 'm'
                continue
            }
            out.unicodeScalars.append(scalars[i])
            i += 1
        }
        return out
    }
}

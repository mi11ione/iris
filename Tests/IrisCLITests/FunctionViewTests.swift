// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `functions` verb.
@Suite("Functions mode")
struct FunctionViewTests {
    func object(_ line: some StringProtocol) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

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
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let first = try #require(run.stdout.split(separator: "\n").first)
        let prefix = "{\"schemaVersion\":1,\"kind\":\"function\",\"symbol\":\"_add42\","
            + "\"address\":\"0x100000328\",\"endAddress\":\"0x100000340\","
            + "\"instructionCount\":6,\"usesPAC\":false,\"instructions\":[{"
        #expect(first.hasPrefix(prefix))
    }

    @Test func addressIsFirstInstructionAndEndIsExclusive() throws {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let lines = run.stdout.split(separator: "\n")
        for line in lines {
            let fields = try #require(object(line))
            let instructions = try #require(fields["instructions"] as? [[String: Any]])
            let address = fields["address"] as? String
            #expect(address == instructions.first?["address"] as? String)
        }
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
            #expect(nested["schemaVersion"] == nil)
            #expect(nested["kind"] as? String == "instruction")
            #expect(nested["address"] is String)
            #expect(nested["encoding"] is String)
            #expect(nested["mnemonic"] is String)
        }
    }

    @Test func nestedObjectPlusSchemaVersionEqualsTheStandaloneLine() {
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
        #expect(nestedObjects(of: "") == [])
        #expect(nestedObjects(of: "{\"kind\":\"census\",\"totalWords\":0}") == [])
    }

    @Test func functionStartsBecomeFunctionsInAddressOrder() {
        let run = runCLI(["functions", "--json", cliFixturePath("hello-arm64")])
        let symbols = run.stdout.split(separator: "\n").compactMap { object($0)?["symbol"] as? String }
        #expect(symbols == ["_add42", "_sum_to", "_helper", "_main"])
    }

    @Test func adjacentStubIsExcludedFromEveryFunction() throws {
        let run = runCLI(["functions", "--json", cliFixturePath("stub-arm64")])
        let lines = run.stdout.split(separator: "\n")
        let symbols = lines.compactMap { object($0)?["symbol"] as? String }
        #expect(symbols == ["_compare", "_main"])
        for line in lines {
            let fields = try #require(object(line))
            let end = try #require(fields["endAddress"] as? String)
            let endValue = try #require(UInt64(end.dropFirst(2), radix: 16))
            #expect(endValue <= 0x1_0000_042C)
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

    @Test func summaryRollupsAreComputedFromInstructions() {
        let plain = runCLI(["functions", "--color", "never", cliFixturePath("hello-arm64")])
        #expect(plain.stdout.contains("_helper") && plain.stdout.contains("  2  "))
        let auth = runCLI(["functions", "--color", "never", cliFixturePath("hello-arm64e")])
        #expect(auth.stdout.contains("yes"))
        #expect(auth.stdout.contains(" no"))
    }

    @Test func leadingRecordsBeforeTheFirstFunctionStartAreDropped() throws {
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD503_201F, 0xD503_201F],
            textAddr: 0x1000,
            extraSize: 16,
            extraCommands: { a in a.linkeditDataCommand(cmd: 0x26, dataoff: 280, datasize: 2) },
            trailer: { a in
                a.pad(to: 280)
                a.bytes.append(contentsOf: [0x08, 0x00])
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
        #expect(function.callCount == 0)
        #expect(!function.usesPointerAuthentication)
    }

    @Test func carverUsesADefaultDiagnosticSink() throws {
        let binary = try #require(walkedBinary(cliFixturePath("dic-arm64.o")))
        let withSpans = binary.codeSections.contains { !$0.dataInCode.isEmpty }
        #expect(withSpans, "fixture must carry data-in-code spans to drive the default sink")
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.isEmpty)
    }

    @Test func carverForwardsSectionDecodeDiagnostics() throws {
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
                a.bytes.append(contentsOf: [0x04, 0x00])
            },
        )
        let wrapping = try #require(walkedBinary(bytes: bytes))
        _ = FunctionCarver.functions(of: wrapping, onStreamDiagnostic: sink)
        #expect(forwarded.contains { $0.section == "__text" })
        #expect(forwarded.contains { if case .addressSpaceWrapped = $0.kind { true } else { false } })
    }

    @Test func wrappingSectionWithoutFunctionStartsDoesNotCrash() throws {
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: UInt64.max - 7,
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.isEmpty)
    }

    @Test func wrappingSectionWithAFunctionStartDoesNotCrash() throws {
        let textAddr = UInt64.max - 7
        let bytes = minimalBinary(
            words: [0xD503_201F, 0xD503_201F, 0xD65F_03C0],
            textAddr: textAddr,
            extraSize: 16,
            extraCommands: { a in a.linkeditDataCommand(cmd: 0x26, dataoff: 280, datasize: 2) },
            trailer: { a in
                a.pad(to: 280)
                a.bytes.append(contentsOf: [0x04, 0x00])
            },
        )
        let binary = try #require(walkedBinary(bytes: bytes))
        let functions = FunctionCarver.functions(of: binary)
        #expect(functions.count >= 0)
        let run = withTemporaryFile(bytes: bytes) { runCLI(["functions", "--color", "never", $0]) }
        #expect(run.status == CLI.exitSuccess)
        let json = withTemporaryFile(bytes: bytes) { runCLI(["functions", "--json", $0]) }
        #expect(json.status == CLI.exitSuccess)
    }

    @Test func binaryWithoutFunctionStartsPrintsNoFunctions() {
        let human = runCLI(["functions", "--color", "never", cliFixturePath("dic-arm64.o")])
        #expect(human.status == CLI.exitSuccess)
        #expect(human.stdout.contains("(no functions)"))
        let json = runCLI(["functions", "--json", cliFixturePath("dic-arm64.o")])
        #expect(json.status == CLI.exitSuccess)
        #expect(json.stdout.isEmpty)
    }

    @Test func summaryColorsWhenEnabled() {
        let colored = runCLI(["functions", "--color", "always", cliFixturePath("hello-arm64")], tty: true)
        #expect(colored.stdout.contains("\u{1B}["))
        let stripped = stripANSI(colored.stdout)
        #expect(normalizedToGolden(stripped) == golden("hello-arm64.functions.txt"))
    }

    @Test func jsonModeNeverColors() {
        let run = runCLI(["functions", "--json", "--color", "always", cliFixturePath("hello-arm64")], tty: true)
        #expect(!run.stdout.contains("\u{1B}"))
    }

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
                if i < scalars.count { i += 1 }
                continue
            }
            out.unicodeScalars.append(scalars[i])
            i += 1
        }
        return out
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the `--json` NDJSON stream against the documented schema
/// (the JSONOutput DocC article): every line parses as one JSON object,
/// carries every required field with the right type, matches the locked
/// golden, and spot-checks decode values; plus the string-escape rules
/// the hand-rolled emitter implements.
@Suite("NDJSON output")
struct JSONOutputTests {
    /// Parse one NDJSON line into a JSON object.
    func object(_ line: some StringProtocol) -> [String: Any]? {
        let data = Data(line.utf8)
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }

    static let requiredFields = [
        "schemaVersion", "kind", "address", "encoding", "mnemonic", "text",
        "category", "operands", "reads", "writes", "branchClass",
        "memoryAccess", "ordering", "flagEffect", "isData", "isUndefined",
    ]

    @Test func everyLineParsesWithRequiredFields() throws {
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        #expect(run.status == CLI.exitSuccess)
        let lines = run.stdout.split(separator: "\n")
        #expect(lines.count == 54)
        for line in lines {
            let fields = try #require(object(line), "unparseable NDJSON line: \(line)")
            for required in Self.requiredFields {
                #expect(fields[required] != nil, "missing \(required) in: \(line)")
            }
            #expect(fields["schemaVersion"] as? Int == JSONText.schemaVersion)
            #expect(fields["kind"] as? String == "instruction")
            let address = try #require(fields["address"] as? String)
            #expect(address.hasPrefix("0x"))
            let encoding = try #require(fields["encoding"] as? String)
            #expect(encoding.count == 10)
            let flagEffect = try #require(fields["flagEffect"] as? [String: Any])
            #expect(flagEffect["reads"] is String)
            #expect(flagEffect["writes"] is String)
            #expect(fields["operands"] is [Any])
            #expect(fields["reads"] is [Any])
            #expect(fields["ordering"] is [Any])
        }
    }

    @Test func streamMatchesGolden() {
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        #expect(run.stdout == golden("hello-arm64.ndjson"))
    }

    @Test func stubStreamMatchesGolden() {
        let run = runCLI(["--json", cliFixturePath("stub-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("stub-arm64.ndjson"))
    }

    @Test func instructionsCarryContainingSymbol() throws {
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        // _main's call to _helper reports _main as its containing function
        // and _helper as its target.
        let callLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"branchTarget\":\"0x100000398\"") })
        let fields = try #require(object(callLine))
        #expect(fields["symbol"] as? String == "_main")
        #expect(fields["targetSymbol"] as? String == "_helper")
    }

    @Test func branchTargetSymbolNamesTheStubImport() throws {
        let run = runCLI(["--json", cliFixturePath("stub-arm64")])
        let stubLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"branchTarget\":\"0x10000042c\"") })
        let fields = try #require(object(stubLine))
        #expect(fields["symbol"] as? String == "_compare")
        #expect(fields["targetSymbol"] as? String == "_strcoll")
    }

    @Test func branchTargetSymbolUsesOffsetForm() throws {
        // hello-arm64's intra-function back-branch lands past a symbol in
        // the same section, so targetSymbol is the name+0x<delta> form.
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        let offsetLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"branchTarget\":\"0x10000038c\"") })
        #expect(try #require(object(offsetLine))["targetSymbol"] as? String == "_sum_to+0x4c")
    }

    @Test func strippedBinaryReportsSubLabelAsSymbol() throws {
        // No symbol table: the containing function is a sub_ label, and
        // the stub import still resolves as targetSymbol.
        let run = runCLI(["--json", cliFixturePath("stub-stripped")])
        let stubLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"branchTarget\":\"0x10000042c\"") })
        let fields = try #require(object(stubLine))
        #expect(fields["symbol"] as? String == "sub_100000410")
        #expect(fields["targetSymbol"] as? String == "_strcoll")
    }

    @Test func directDecodeModesOmitSymbolFields() throws {
        // Raw bytes carry no symbols, so neither field is emitted.
        let run = runCLI(["--json", "0x97ffffdf"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        #expect(fields["symbol"] == nil)
        #expect(fields["targetSymbol"] == nil)
    }

    @Test func symbolContextMemberwiseInitComposes() {
        // The memberwise init pairs a label set and a resolver directly;
        // instructionLine reads both through it.
        let labels = FunctionLabels(functionStarts: [0x1000], symbols: .empty)
        let symbolizer = BranchSymbolizer(symbols: .empty, sections: [], stubTargets: [0x2000: "_imported"])
        let context = JSONText.SymbolContext(labels: labels, symbolizer: symbolizer)
        #expect(context.labels.containing(0x1004) == "sub_1000")
        #expect(context.symbolizer.resolve(target: 0x2000)?.name == "_imported")
    }

    @Test func branchLineCarriesTargetAndSemantics() throws {
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        let blLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"mnemonic\":\"bl\"") })
        let fields = try #require(object(blLine))
        #expect(fields["branchTarget"] as? String == "0x100000328")
        #expect(fields["branchClass"] as? String == "call")
        #expect(fields["writes"] as? [String] == ["x30"])
        #expect(fields["text"] as? String == "bl #-132")
        #expect(fields["operands"] as? [String] == ["#-132"])
    }

    @Test func dataMarkerLineIsHonest() throws {
        let run = runCLI(["--json", cliFixturePath("dic-linked")])
        let marker = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"isData\":true") })
        let fields = try #require(object(marker))
        #expect(fields["category"] as? String == "dataInCodeMarker")
        #expect(fields["operands"] as? [String] == [])
        #expect(fields["reads"] as? [String] == [])
        #expect(fields["branchTarget"] == nil)
    }

    @Test func undefinedWordLine() throws {
        let run = runCLI(["--json", "0x02000000"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        #expect(fields["isUndefined"] as? Bool == true)
        #expect(fields["category"] as? String == "undefined")
        #expect(fields["mnemonic"] as? String == "undefined")
        #expect(fields["operands"] as? [String] == [])
    }

    @Test func truncatedTailLine() throws {
        let run = runCLI(["--json", "--bytes", "aa bb"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        #expect(fields["category"] as? String == "truncatedTail")
        #expect(fields["encoding"] as? String == "0x0000bbaa")
        #expect(fields["isUndefined"] as? Bool == false)
        #expect(fields["isData"] as? Bool == false)
    }

    @Test func pcRelativeTargetAppears() throws {
        // adrp x1, #0 at address 0: page target resolves to 0x0.
        let run = runCLI(["--json", "0x90000001"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        #expect(fields["pcRelativeTarget"] as? String == "0x0")
        #expect(fields["branchTarget"] == nil)
    }

    @Test func memoryAndOrderingFields() throws {
        // ldar x0, [x1]: acquire-ordered load.
        let run = runCLI(["--json", "0xc8dffc20"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        #expect(fields["memoryAccess"] as? String == "load")
        #expect(fields["ordering"] as? [String] == ["acquire"])

        // stlr x0, [x1]: release-ordered store.
        let release = runCLI(["--json", "0xc89ffc20"])
        let releaseFields = try #require(object(release.stdout.trimmingCharacters(in: .newlines)))
        #expect(releaseFields["memoryAccess"] as? String == "store")
        #expect(releaseFields["ordering"] as? [String] == ["release"])

        // casal x0, x1, [x2]: acquire-release atomic.
        let both = runCLI(["--json", "0xc8e0fc41"])
        let bothFields = try #require(object(both.stdout.trimmingCharacters(in: .newlines)))
        #expect(bothFields["memoryAccess"] as? String == "atomic")
        #expect(bothFields["ordering"] as? [String] == ["acquire", "release"])
    }

    @Test func flagWritesRender() throws {
        // adds x0, x1, #1 writes NZCV.
        let run = runCLI(["--json", "0xb1000420"])
        let fields = try #require(object(run.stdout.trimmingCharacters(in: .newlines)))
        let flagEffect = try #require(fields["flagEffect"] as? [String: Any])
        #expect(flagEffect["writes"] as? String == "nzcv")
        #expect(flagEffect["reads"] as? String == "")
    }

    @Test func stringEscapingIsJSONSafe() throws {
        let hostile = "quote\" backslash\\ newline\n return\r tab\t bell\u{7} unicode\u{1}end"
        let literal = JSONText.string(hostile)
        #expect(literal == "\"quote\\\" backslash\\\\ newline\\n return\\r tab\\t bell\\u0007 unicode\\u0001end\"")
        let decoded = try JSONSerialization.jsonObject(with: Data("[\(literal)]".utf8)) as? [String]
        #expect(decoded == [hostile])
    }

    @Test func arrayEmissionMatchesSerialization() {
        #expect(JSONText.array([]) == "[]")
        #expect(JSONText.array(["a", "b\"c"]) == "[\"a\",\"b\\\"c\"]")
    }

    @Test func categoryNamesAreStable() {
        #expect(JSONText.categoryName(.undefined) == "undefined")
        #expect(JSONText.categoryName(.dataInCodeMarker) == "dataInCodeMarker")
        #expect(JSONText.categoryName(.truncatedTail) == "truncatedTail")
        #expect(JSONText.categoryName(.dataProcessingImmediate) == "dataProcessingImmediate")
        #expect(JSONText.categoryName(.branchesExceptionSystem) == "branchesExceptionSystem")
        #expect(JSONText.categoryName(.dataProcessingRegister) == "dataProcessingRegister")
        #expect(JSONText.categoryName(.loadsAndStores) == "loadsAndStores")
        #expect(JSONText.categoryName(.simdAndFP) == "simdAndFP")
        #expect(JSONText.categoryName(.pointerAuthentication) == "pointerAuthentication")
        #expect(JSONText.categoryName(.crypto) == "crypto")
        #expect(JSONText.categoryName(.amx) == "amx")
        #expect(JSONText.categoryName(.memoryTagging) == "memoryTagging")
        #expect(JSONText.categoryName(.sve) == "sve")
        #expect(JSONText.categoryName(.sme) == "sme")
    }

    @Test func jsonModeNeverColors() {
        let run = runCLI(["--json", "--color", "always", "0xd503201f"], tty: true)
        #expect(!run.stdout.contains("\u{1B}"))
    }

    // MARK: Scalable state

    @Test func baseISALinesCarryNoScalableFields() throws {
        // The scalable fields are absent-when-empty, so every pre-scalable
        // consumer sees a byte-identical line.
        let line = try #require(object(runCLI(["--json", "0xd503201f"]).stdout))
        #expect(line["scalableReads"] == nil)
        #expect(line["scalableWrites"] == nil)
        #expect(line["scalableEffect"] == nil)
    }

    @Test func predicatedSVEWritesItsGoverningPredicate() throws {
        // subr z1.d, p0/m, z1.d, z31.d — p0 governs, so the write is
        // partial and the record says so.
        let line = try #require(object(runCLI(["--json", "0x04C303E1"]).stdout))
        let reads = try #require(line["scalableReads"] as? [String: Any])
        #expect(reads["predicates"] as? [String] == ["p0"])
        #expect(line["scalableWrites"] == nil)
        #expect(line["scalableEffect"] as? [String] == ["partial-write", "reads-streaming-mode"])
    }

    @Test func smeOuterProductCarriesItsZAMask() throws {
        // fmopa za0.s — tile 0 at .S is the .Q positions {0,4,8,12}, the
        // 0x1111 residue mask, read and written alike.
        let line = try #require(object(runCLI(["--json", "0x8080FC00"]).stdout))
        let reads = try #require(line["scalableReads"] as? [String: Any])
        let writes = try #require(line["scalableWrites"] as? [String: Any])
        #expect(reads["predicates"] as? [String] == ["p7"])
        #expect(reads["za"] as? String == "0x1111")
        #expect(writes["za"] as? String == "0x1111")
    }

    @Test func faultingLoadsCarryFFRAndTheirFaultClass() throws {
        // A first-fault gather reads and writes FFR; the fault class is the
        // effect flag that tells the two apart.
        let firstFault = try #require(object(runCLI(["--json", "0x844F7FC0"]).stdout))
        #expect((firstFault["scalableReads"] as? [String: Any])?["ffr"] as? Bool == true)
        #expect((firstFault["scalableWrites"] as? [String: Any])?["ffr"] as? Bool == true)
        #expect((firstFault["scalableEffect"] as? [String])?.contains("first-faulting") == true)

        let nonFault = try #require(object(runCLI(["--json", "0xA410A000"]).stdout))
        #expect((nonFault["scalableEffect"] as? [String])?.contains("non-faulting") == true)

        let nonTemporal = try #require(object(runCLI(["--json", "0xA400E000"]).stdout))
        #expect((nonTemporal["scalableEffect"] as? [String])?.contains("non-temporal") == true)
    }

    @Test func zt0AppearsOnBothSidesOfMOVT() throws {
        let fromZT0 = try #require(object(runCLI(["--json", "0xC04C03E0"]).stdout))
        #expect((fromZT0["scalableReads"] as? [String: Any])?["zt0"] as? Bool == true)

        let toZT0 = try #require(object(runCLI(["--json", "0xC04E03E0"]).stdout))
        #expect((toZT0["scalableWrites"] as? [String: Any])?["zt0"] as? Bool == true)
    }

    @Test func scalableRenderersCoverTheirWholeVocabulary() {
        #expect(JSONText.scalableSet(.empty) == nil)
        #expect(JSONText.scalableEffectNames(.none).isEmpty)
        // Every flag, in bit order. The two streaming-mode transition flags
        // have no decoder that sets them today, so they are pinned here on a
        // built value rather than on a word.
        let all: ScalableEffect = [
            .partialWrite, .readsStreamingMode, .writesStreamingMode, .writesZAEnable,
            .firstFaulting, .nonFaulting, .nonTemporal,
        ]
        #expect(JSONText.scalableEffectNames(all) == [
            "partial-write", "reads-streaming-mode", "writes-streaming-mode",
            "writes-za-enable", "first-faulting", "non-faulting", "non-temporal",
        ])
    }
}

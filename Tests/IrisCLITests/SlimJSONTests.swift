// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates `--slim`: it drops the zero-signal constants and empty fields,
/// keeps field order, and is a usage error without `--json`.
@Suite("Slim JSON projection")
struct SlimJSONTests {
    func object(_ line: some StringProtocol) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

    func sameJSON(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case let (a as [String: Any], b as [String: Any]):
            a.count == b.count && a.allSatisfy { sameJSON($0.value, b[$0.key]) }
        case let (a as [Any], b as [Any]):
            a.count == b.count && zip(a, b).allSatisfy { sameJSON($0, $1) }
        default:
            "\(a ?? "·")" == "\(b ?? "·")"
        }
    }

    @Test func sameJSONComparesAbsentValues() {
        #expect(sameJSON(nil, nil))
        #expect(!sameJSON(nil, 1))
        #expect(!sameJSON(1, nil))
    }

    @Test func slimStreamMatchesGolden() {
        let run = runCLI(["--json", "--slim", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("strings-arm64.slim.ndjson"))
    }

    @Test func slimFunctionsMatchGolden() {
        let run = runCLI(["functions", "--json", "--slim", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == golden("strings-arm64.functions.slim.ndjson"))
    }

    @Test func slimDropsConstantsAndEmpties() throws {
        let run = runCLI(["--json", "--slim", cliFixturePath("hello-arm64")])
        for line in run.stdout.split(separator: "\n") {
            let fields = try #require(object(line))
            #expect(fields["kind"] == nil)
            #expect(fields["schemaVersion"] == nil)
            #expect((fields["ordering"] as? [Any])?.isEmpty != true)
            if let branch = fields["branchClass"] as? String { #expect(branch != "none") }
            if let memory = fields["memoryAccess"] as? String { #expect(memory != "none") }
            #expect(fields["isData"] == nil)
            #expect(fields["isUndefined"] == nil)
        }
    }

    @Test func slimKeepsSignalBearingFields() throws {
        let nop = try #require(object(runCLI(["decode", "--json", "--slim", "0xd503201f"]).stdout))
        #expect(nop["mnemonic"] as? String == "nop")
        #expect(nop["flagEffect"] == nil && nop["ordering"] == nil && nop["branchClass"] == nil)
        #expect(nop["reads"] as? [String] == [] && nop["writes"] as? [String] == [])

        let call = try #require(object(runCLI(["decode", "--json", "--slim", "0x97ffffdf"]).stdout))
        #expect(call["branchClass"] as? String == "call")
        #expect(call["branchTarget"] is String)

        let flags = try #require(object(runCLI(["decode", "--json", "--slim", "0xb1000420"]).stdout))
        let flagEffect = try #require(flags["flagEffect"] as? [String: Any])
        #expect(flagEffect["writes"] as? String == "nzcv")

        let acquire = try #require(object(runCLI(["decode", "--json", "--slim", "0xc8dffc20"]).stdout))
        #expect(acquire["ordering"] as? [String] == ["acquire"])
        #expect(acquire["memoryAccess"] as? String == "load")
    }

    @Test func slimDataAndUndefinedWitnessesAppearOnlyWhenTrue() throws {
        let undefined = try #require(object(runCLI(["decode", "--json", "--slim", "0x02000000"]).stdout))
        #expect(undefined["isUndefined"] as? Bool == true)
        #expect(undefined["isData"] == nil)

        let dataLine = try #require(runCLI(["--json", "--slim", cliFixturePath("dic-linked")]).stdout
            .split(separator: "\n").first { $0.contains("\"isData\":true") })
        let data = try #require(object(dataLine))
        #expect(data["isData"] as? Bool == true)
        #expect(data["isUndefined"] == nil)
    }

    @Test func slimDirectStreamKeepsReferencedAndCharFields() throws {
        let run = runCLI(["--json", "--slim", cliFixturePath("strings-arm64")])
        let stringLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"referencedString\"") })
        #expect(object(stringLine)?["referencedSection"] as? String == "__TEXT,__cstring")
        let charLine = try #require(run.stdout.split(separator: "\n").first { $0.contains("\"charLiteral\"") })
        #expect(object(charLine)?["charLiteral"] is String)
    }

    @Test func slimFunctionsDropPerInstructionSymbol() throws {
        let run = runCLI(["functions", "--json", "--slim", cliFixturePath("hello-arm64")])
        for line in run.stdout.split(separator: "\n") {
            let function = try #require(object(line))
            #expect(function["kind"] == nil && function["schemaVersion"] == nil)
            #expect(function["symbol"] is String)
            let instructions = try #require(function["instructions"] as? [[String: Any]])
            for inst in instructions {
                #expect(inst["symbol"] == nil, "per-instruction symbol must be dropped")
            }
        }
    }

    @Test func functionsCarryUsesPACMirroringTheTable() throws {
        let full = runCLI(["functions", "--json", cliFixturePath("hello-arm64e")])
        #expect(full.stdout.contains("\"usesPAC\":true"))
        #expect(full.stdout.contains("\"usesPAC\":false"))
        let slim = runCLI(["functions", "--json", "--slim", cliFixturePath("hello-arm64e")])
        var pacFunctions = 0
        var nonPACFunctions = 0
        for line in slim.stdout.split(separator: "\n") {
            let function = try #require(object(line))
            if function["usesPAC"] as? Bool == true {
                pacFunctions += 1
            } else {
                #expect(function["usesPAC"] == nil, "slim must omit usesPAC when false")
                nonPACFunctions += 1
            }
        }
        #expect(pacFunctions > 0)
        #expect(nonPACFunctions > 0)
    }

    @Test func slimStreamKeepsPerInstructionSymbol() throws {
        let run = runCLI(["--json", "--slim", cliFixturePath("hello-arm64")])
        let line = try #require(run.stdout.split(separator: "\n").first)
        #expect(object(line)?["symbol"] as? String == "_add42")
    }

    @Test func slimIsAFaithfulSubsetOfDefault() throws {
        let full = runCLI(["--json", cliFixturePath("strings-arm64")]).stdout.split(separator: "\n")
        let slim = runCLI(["--json", "--slim", cliFixturePath("strings-arm64")]).stdout.split(separator: "\n")
        #expect(full.count == slim.count)
        for (f, s) in zip(full, slim) {
            let of = try #require(object(f))
            let os = try #require(object(s))
            for (key, value) in os {
                #expect(sameJSON(of[key], value), "slim \(key) diverges from default")
            }
            for (key, value) in of where os[key] == nil {
                let droppable = ["kind", "schemaVersion"].contains(key)
                    || (key == "ordering" && (value as? [Any])?.isEmpty == true)
                    || (key == "flagEffect" && (value as? [String: Any]).map { $0["reads"] as? String == "" && $0["writes"] as? String == "" } == true)
                    || (key == "branchClass" && value as? String == "none")
                    || (key == "memoryAccess" && value as? String == "none")
                    || (key == "isData" && value as? Bool == false)
                    || (key == "isUndefined" && value as? Bool == false)
                #expect(droppable, "default key \(key) dropped by slim is signal-bearing")
            }
        }
    }

    @Test func defaultJSONIsUnchangedByTheSlimFeature() {
        let run = runCLI(["--json", cliFixturePath("hello-arm64")])
        #expect(run.stdout == golden("hello-arm64.ndjson"))
    }

    @Test func slimIsSmallerThanDefault() {
        let full = runCLI(["functions", "--json", cliFixturePath("strings-arm64")]).stdout
        let slim = runCLI(["functions", "--json", "--slim", cliFixturePath("strings-arm64")]).stdout
        #expect(slim.utf8.count < full.utf8.count)
    }

    @Test func slimKeepsScalableStateVerbatim() throws {
        let slim = try #require(object(runCLI(["decode", "--json", "--slim", "0x04C303E1"]).stdout))
        let full = try #require(object(runCLI(["decode", "--json", "0x04C303E1"]).stdout))
        #expect((slim["scalableReads"] as? [String: Any])?["predicates"] as? [String] == ["p0"])
        #expect(slim["scalableEffect"] as? [String] == full["scalableEffect"] as? [String])

        let base = try #require(object(runCLI(["decode", "--json", "--slim", "0xd503201f"]).stdout))
        #expect(base["scalableReads"] == nil && base["scalableEffect"] == nil)
    }
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates the CLI end to end over real system binaries under
/// `IRIS_CLI_SYSTEM_SMOKE=1`.
@Suite(
    "System binary smoke",
    .enabled(if: ProcessInfo.processInfo.environment["IRIS_CLI_SYSTEM_SMOKE"] == "1"),
)
struct SystemBinarySmokeTests {
    static let candidates = ["/bin/ls", "/bin/zsh", "/usr/lib/dyld"]

    static var present: [String] {
        candidates.filter { FileManager.default.isReadableFile(atPath: $0) }
    }

    @Test(arguments: present)
    func listingStructure(path: String) throws {
        let binary = try #require(walkedBinary(path))
        #expect(!binary.codeSections.isEmpty)
        let run = runCLI(["--color", "never", path])
        #expect(run.status == CLI.exitSuccess)

        var recordCount = 0
        for section in binary.codeSections {
            recordCount += section.instructions(features: binary.features).count
        }
        let instructionLines = run.stdout.split(separator: "\n").filter { line in
            line.first.map { $0.isHexDigit && ($0.isNumber || $0.isLowercase) } == true && line.contains(": ")
        }
        #expect(instructionLines.count == recordCount)

        if binary.symbols.count > 0, !binary.functionStarts.isEmpty {
            #expect(run.stdout.contains(":\n"))
        }
    }

    @Test(arguments: present)
    func jsonStructure(path: String) throws {
        let run = runCLI(["--json", path])
        #expect(run.status == CLI.exitSuccess)
        let lines = run.stdout.split(separator: "\n")
        #expect(!lines.isEmpty)
        for line in lines {
            let object = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
            let parsed = try #require(object, "unparseable NDJSON over \(path)")
            #expect(parsed["schemaVersion"] as? Int == 1)
            #expect(parsed["address"] is String)
        }
    }

    @Test(arguments: present)
    func censusAddsUp(path: String) throws {
        let binary = try #require(walkedBinary(path))
        var census = Census()
        for section in binary.codeSections {
            census.add(section.instructions(features: binary.features))
        }
        let total = census.mnemonicCounts.values.reduce(0, +)
            + census.undefinedWords + census.dataWords + census.truncatedTails
        #expect(total == census.totalWords)
        #expect(census.totalWords > 0)

        let run = runCLI(["stats", path])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout.contains("total words        \(census.totalWords)\n"))
    }

    @Test(arguments: present)
    func semanticsModeSucceeds(path: String) {
        let run = runCLI(["--color", "never", "--semantics", path])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout.contains("; reads=") || run.stdout.contains("; writes="))
    }
}

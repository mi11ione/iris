// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation
import Iris
import IrisCLICore
import Testing

/// Validates `disasm` scoping: `--function <name>` limits output to one
/// function's instructions, `--range <start>:<end>` to a half-open VM
/// window, both compose with `--json` / `--semantics` / `--color`, and the
/// error paths (an unknown function, a malformed range) exit cleanly.
@Suite("Disasm scoping")
struct DisasmScopingTests {
    func object(_ line: some StringProtocol) -> [String: Any]? {
        (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any]
    }

    // MARK: - -function

    @Test func functionScopeMatchesGolden() {
        let run = runCLI(["disasm", "--function", "_greet", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(normalizedToGolden(run.stdout) == golden("strings-arm64.greet.listing.txt"))
    }

    @Test func functionScopeEmitsOnlyThatFunction() {
        let run = runCLI(["disasm", "--function", "_classify", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("_classify:"))
        // The other functions and the stub island are excluded.
        #expect(!run.stdout.contains("_greet:"))
        #expect(!run.stdout.contains("_main:"))
        #expect(!run.stdout.contains("__stubs"))
    }

    @Test func functionScopeComposesWithJSON() {
        let run = runCLI(["disasm", "--function", "_classify", "--json", cliFixturePath("strings-arm64")])
        let lines = run.stdout.split(separator: "\n")
        #expect(!lines.isEmpty)
        for line in lines {
            #expect(object(line)?["symbol"] as? String == "_classify")
        }
    }

    @Test func functionScopeComposesWithSlimAndSemantics() {
        let slim = runCLI(["disasm", "--function", "_classify", "--json", "--slim", cliFixturePath("strings-arm64")])
        #expect(slim.status == CLI.exitSuccess)
        #expect(slim.stdout.contains("\"charLiteral\":\"A\""))
        let semantics = runCLI(["disasm", "--function", "_classify", "--semantics", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(semantics.stdout.contains("_classify:"))
        #expect(semantics.stdout.contains("; reads="))
    }

    @Test func unknownFunctionIsACleanUsageError() {
        let run = runCLI(["disasm", "--function", "_nope", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitUsage)
        #expect(run.stdout.isEmpty)
        #expect(run.stderr.contains("no function named '_nope'"))
        // The error lists what the binary does carry.
        #expect(run.stderr.contains("_greet"))
    }

    @Test func functionScopeOnABinaryWithNoFunctionsReportsThat() {
        // A binary with code but no LC_FUNCTION_STARTS and no symbols carves
        // no functions, so the error names that rather than an empty list.
        let bytes = minimalBinary(words: [0xD503_201F]) // one nop, no symtab/starts
        let run = withTemporaryFile(bytes: bytes) { path in
            runCLI(["disasm", "--function", "_main", path])
        }
        #expect(run.status == CLI.exitUsage)
        #expect(run.stderr.contains("no function named '_main'"))
        #expect(run.stderr.contains("this binary lists no functions"))
    }

    @Test func functionScopeOnAStrippedBinaryUsesSubLabels() {
        // A stripped binary's functions are sub_<hex>; the scope resolves
        // by that name.
        let run = runCLI(["disasm", "--function", "sub_100000328", "--color", "never", cliFixturePath("hello-stripped")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout.contains("sub_100000328:"))
        #expect(!run.stdout.contains("sub_100000398:"))
    }

    // MARK: - -range

    @Test func rangeScopeEmitsOnlyTheWindow() {
        // [0x100000460, 0x100000478): the first six words of _greet.
        let run = runCLI(["disasm", "--range", "0x100000460:0x100000478", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        let lines = run.stdout.split(separator: "\n").filter { $0.contains(": ") && $0.contains("  ") }
        // Exactly the records with start <= address < end.
        #expect(run.stdout.contains("100000460: d10083ff"))
        #expect(run.stdout.contains("100000474: f90003e8"))
        #expect(!run.stdout.contains("100000478:")) // end is exclusive
        #expect(lines.count == 6)
    }

    @Test func rangeScopeKeepsTheIdiomResolutionAtTheBoundary() {
        // The adrp at 0x46c and its completing add at 0x470 are both in
        // window, so the string annotation still resolves.
        let run = runCLI(["disasm", "--range", "0x100000460:0x100000478", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.stdout.contains("add x8, x8, #1268 ; \"world\""))
    }

    @Test func rangeScopeComposesWithJSON() throws {
        let run = runCLI(["disasm", "--range", "0x100000490:0x1000004a0", "--json", cliFixturePath("strings-arm64")])
        let lines = run.stdout.split(separator: "\n")
        for line in lines {
            let address = try #require(object(line)?["address"] as? String)
            let value = try #require(UInt64(address.dropFirst(2), radix: 16))
            #expect(value >= 0x1_0000_0490 && value < 0x1_0000_04A0)
        }
    }

    @Test func rangeSelectingNothingEmitsOnlyTheHeader() {
        // A window in no section prints the path header and no section
        // blocks (the lazy section header never fires).
        let run = runCLI(["disasm", "--range", "0x1:0x2", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout.contains("(arm64):"))
        #expect(!run.stdout.contains("__TEXT,__text:"))
    }

    @Test func malformedRangeIsACleanUsageErrorBeforeOpeningTheFile() {
        let run = runCLI(["disasm", "--range", "garbage", cliFixturePath("strings-arm64")])
        #expect(run.status == CLI.exitUsage)
        #expect(run.stdout.isEmpty)
        #expect(run.stderr.contains("--range wants start:end"))
    }

    @Test func decimalRangeWorks() {
        // The same window in decimal as 0x100000490:0x1000004a0
        // (0x100000490 == 4294968464, 0x1000004a0 == 4294968480).
        let hexRun = runCLI(["disasm", "--range", "0x100000490:0x1000004a0", "--color", "never", cliFixturePath("strings-arm64")])
        let decRun = runCLI(["disasm", "--range", "4294968464:4294968480", "--color", "never", cliFixturePath("strings-arm64")])
        #expect(decRun.stdout == hexRun.stdout)
        #expect(!decRun.stdout.isEmpty)
        #expect(decRun.stdout.contains("100000490:"))
    }
}

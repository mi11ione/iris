// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates `(cputype, cpusubtype)` naming and selection mapping: the
/// lipo-style names for known pairs, the identifying fallback for
/// unknown ones, and which pairs satisfy which `--arch` selection.
@Suite("Architecture naming")
struct ArchitectureNamingTests {
    @Test func arm64FlavorNames() {
        #expect(ArchitectureName.name(cputype: 0x0100_000C, cpusubtype: 0) == "arm64")
        #expect(ArchitectureName.name(cputype: 0x0100_000C, cpusubtype: 1) == "arm64v8")
        #expect(ArchitectureName.name(cputype: 0x0100_000C, cpusubtype: 2) == "arm64e")
        #expect(ArchitectureName.name(cputype: 0x0100_000C, cpusubtype: 9) == "arm64 (subtype 9)")
    }

    @Test func capabilityBitsAreMasked() {
        // arm64e slices ship with high capability bits (0x80000002 and
        // friends); only the low feature byte names the flavor.
        #expect(ArchitectureName.name(cputype: 0x0100_000C, cpusubtype: Int32(bitPattern: 0x8000_0002)) == "arm64e")
        #expect(ArchitectureName.selection(cputype: 0x0100_000C, cpusubtype: Int32(bitPattern: 0xC000_0002)) == .arm64e)
    }

    @Test func foreignArchitectureNames() {
        #expect(ArchitectureName.name(cputype: 0x0200_000C, cpusubtype: 0) == "arm64_32")
        #expect(ArchitectureName.name(cputype: 0x0100_0007, cpusubtype: 3) == "x86_64")
        #expect(ArchitectureName.name(cputype: 0x0000_0007, cpusubtype: 3) == "i386")
        #expect(ArchitectureName.name(cputype: 0x0000_000C, cpusubtype: 9) == "arm")
        #expect(ArchitectureName.name(cputype: 18, cpusubtype: 0) == "cputype(18,0)")
    }

    @Test func selectionMapping() {
        #expect(ArchitectureName.selection(cputype: 0x0100_000C, cpusubtype: 0) == .arm64)
        #expect(ArchitectureName.selection(cputype: 0x0100_000C, cpusubtype: 1) == .arm64)
        #expect(ArchitectureName.selection(cputype: 0x0100_000C, cpusubtype: 2) == .arm64e)
        #expect(ArchitectureName.selection(cputype: 0x0100_000C, cpusubtype: 9) == nil)
        #expect(ArchitectureName.selection(cputype: 0x0100_0007, cpusubtype: 3) == nil)
    }

    @Test func topLevelHelpNamesEveryVerbAndGlobal() {
        for needle in ["usage:", "verbs:", "disasm", "decode", "stats", "functions",
                       "--version", "--help", "exit codes:"]
        {
            #expect(CLI.helpText.contains(needle), "top-level help is missing \(needle)")
        }
        #expect(CLI.helpText(for: nil) == CLI.helpText)
    }

    @Test func eachVerbHelpNamesItsOwnFlags() {
        #expect(CLI.helpText(for: .disasm).contains("--arch"))
        #expect(CLI.helpText(for: .disasm).contains("--semantics"))
        #expect(CLI.helpText(for: .disasm).contains("--quiet"))
        #expect(!CLI.helpText(for: .disasm).contains("--features"))

        #expect(CLI.helpText(for: .decode).contains("--features"))
        #expect(CLI.helpText(for: .decode).contains("--semantics"))
        #expect(CLI.helpText(for: .decode).contains("--bytes"))
        #expect(!CLI.helpText(for: .decode).contains("--arch"))

        #expect(CLI.helpText(for: .stats).contains("--arch"))
        #expect(CLI.helpText(for: .stats).contains("--json"))
        #expect(!CLI.helpText(for: .stats).contains("--semantics"))

        #expect(CLI.helpText(for: .functions).contains("--json"))
        #expect(CLI.helpText(for: .functions).contains("--color"))
        #expect(!CLI.helpText(for: .functions).contains("--semantics"))

        // Every verb help names its usage and the help flag.
        for verb in Verb.allCases {
            #expect(CLI.helpText(for: verb).contains("usage:"))
            #expect(CLI.helpText(for: verb).contains("--help, -h"))
        }
    }

    @Test func disasmHelpNamesScopingAndAnnotationFlags() {
        let help = CLI.helpText(for: .disasm)
        #expect(help.contains("--function"))
        #expect(help.contains("--range"))
        #expect(help.contains("--slim"))
        // The referenced-data annotation is described.
        #expect(help.contains("\"the string\""))
    }

    @Test func slimIsDocumentedWhereverJSONIsAccepted() {
        // --slim shapes --json, so the verbs that emit JSON name it; stats
        // emits one census object, the others NDJSON.
        for verb in [Verb.disasm, .decode, .stats, .functions] {
            #expect(CLI.helpText(for: verb).contains("--slim"), "\(verb) help should name --slim")
        }
    }
}

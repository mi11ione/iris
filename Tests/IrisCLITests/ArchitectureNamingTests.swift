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

    @Test func helpTextNamesEverything() {
        for needle in [
            "usage:", "--arch", "--features", "--semantics", "--json",
            "--stats", "--color", "--quiet", "--bytes", "--help",
            "exit codes:",
        ] {
            #expect(CLI.helpText.contains(needle), "help is missing \(needle)")
        }
    }
}

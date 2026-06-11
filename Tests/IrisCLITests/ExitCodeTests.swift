// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates the CLI's exit-code contract (0 success / 1 usage /
/// 2 unreadable-or-not-Mach-O / 3 nothing-to-decode) and its stream
/// discipline: listings on stdout, errors and diagnostics on stderr,
/// `--quiet` silencing diagnostics but never errors.
@Suite("Exit codes and stream discipline")
struct ExitCodeTests {
    @Test func successIsZero() {
        let run = runCLI([cliFixturePath("hello-arm64")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stderr.isEmpty)
        #expect(!run.stdout.isEmpty)
    }

    @Test func helpPrintsToStdoutAndSucceeds() {
        let run = runCLI(["--help"])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == CLI.helpText)
        #expect(run.stderr.isEmpty)
    }

    @Test func versionPrintsToStdoutAndSucceeds() {
        let run = runCLI(["--version"])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == "iris \(CLI.version)\n")
        #expect(CLI.version == "0.2.0")
        #expect(run.stderr.isEmpty)
    }

    @Test func usageErrorIsOne() {
        let run = runCLI(["--bogus-flag"])
        #expect(run.status == CLI.exitUsage)
        #expect(run.stdout.isEmpty)
        #expect(run.stderr == "iris: error: unknown option '--bogus-flag'\nrun 'iris --help' for usage\n")
    }

    @Test func unreadablePathIsTwo() {
        let run = runCLI(["/nonexistent/iris/test/path"])
        #expect(run.status == CLI.exitNotMachO)
        #expect(run.stdout.isEmpty)
        #expect(run.stderr == "iris: error: cannot open or map '/nonexistent/iris/test/path'\n")
    }

    @Test func nonMachOIsTwo() {
        let path = cliFixturePath("not-macho.txt")
        let run = runCLI([path])
        #expect(run.status == CLI.exitNotMachO)
        #expect(run.stderr == "iris: error: '\(path)' has no Mach-O or fat magic (first word 0x73696874)\n")
    }

    @Test func archUnavailableIsThree() {
        let path = cliFixturePath("hello-arm64")
        let run = runCLI(["--arch", "arm64e", path])
        #expect(run.status == CLI.exitNoCode)
        #expect(run.stderr == "iris: error: no arm64e slice in '\(path)' (available: arm64)\n")
    }

    @Test func defaultSelectionOnForeignBinaryIsThree() {
        // No --arch given and nothing ARM64-flavored in the file: the
        // error names the default preference and the available slices.
        var a = MachOAssembler()
        a.machHeader64(cputype: 0x0100_0007, ncmds: 0, sizeofcmds: 0)
        let run = withTemporaryFile(bytes: a.bytes) { runCLI([$0]) }
        #expect(run.status == CLI.exitNoCode)
        #expect(run.stderr.contains("iris: error: no arm64 or arm64e slice in '"))
        #expect(run.stderr.contains("(available: x86_64)\n"))
    }

    @Test func noCodeSectionsIsThree() {
        let path = cliFixturePath("zero-size-section")
        let run = runCLI([path])
        #expect(run.status == CLI.exitNoCode)
        #expect(run.stderr.contains("iris: error: no decodable code sections in '\(path)' (arm64)\n"))
    }

    @Test func diagnosticsReachStderrNotStdout() {
        let run = runCLI([cliFixturePath("bad-symtab")])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stderr.contains("warning: symbol table out of bounds"))
        #expect(!run.stdout.contains("warning:"))
    }

    @Test func quietSuppressesDiagnosticsOnly() {
        let loud = runCLI([cliFixturePath("bad-symtab")])
        let quiet = runCLI(["--quiet", cliFixturePath("bad-symtab")])
        #expect(loud.stderr.contains("warning:"))
        #expect(quiet.stderr.isEmpty)
        #expect(quiet.status == CLI.exitSuccess)
        #expect(quiet.stdout == loud.stdout)

        let quietError = runCLI(["--quiet", "/nonexistent/iris/test/path"])
        #expect(quietError.status == CLI.exitNotMachO)
        #expect(quietError.stderr.contains("iris: error:"))
    }

    @Test func exitCodeConstantsAreDistinct() {
        #expect(CLI.exitSuccess == 0)
        #expect(CLI.exitUsage == 1)
        #expect(CLI.exitNotMachO == 2)
        #expect(CLI.exitNoCode == 3)
    }
}

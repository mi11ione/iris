// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates argv parsing: every flag, every documented usage error,
/// the word/byte-string input grammars, and flag-interaction rules.
@Suite("Command-line parsing")
struct CommandLineParsingTests {
    @Test func helpFlagWinsAnywhere() {
        #expect(ParsedCommandLine.parse(["--help"]) == .help)
        #expect(ParsedCommandLine.parse(["-h"]) == .help)
        #expect(ParsedCommandLine.parse(["some/file", "--help", "--json"]) == .help)
    }

    @Test func versionFlagWinsAnywhere() {
        #expect(ParsedCommandLine.parse(["--version"]) == .version)
        #expect(ParsedCommandLine.parse(["some/file", "--version", "--json"]) == .version)
    }

    @Test func fileInvocationWithEveryFlag() {
        let parsed = ParsedCommandLine.parse([
            "--arch", "arm64e", "--json", "--semantics", "--quiet",
            "--color", "never", "a/binary",
        ])
        let expected = Invocation(
            input: .file(path: "a/binary"),
            arch: .arm64e,
            json: true,
            semantics: true,
            color: .never,
            quiet: true,
        )
        #expect(parsed == .run(expected))
    }

    @Test func wordInput() {
        #expect(ParsedCommandLine.parse(["0xd503201f"]) == .run(Invocation(input: .word(0xD503_201F))))
        #expect(ParsedCommandLine.parse(["0X1F2"]) == .run(Invocation(input: .word(0x1F2))))
    }

    @Test func bytesInput() {
        let expected = Invocation(input: .bytes([0x1F, 0x20, 0x03, 0xD5]))
        #expect(ParsedCommandLine.parse(["--bytes", "1f 20 03 d5"]) == .run(expected))
        #expect(ParsedCommandLine.parse(["--bytes", "1f,20,03,d5"]) == .run(expected))
        #expect(ParsedCommandLine.parse(["--bytes", "1F2003D5"]) == .run(expected))
    }

    @Test func bytesInputAcceptsEveryHexDigitInBothCases() {
        let expected = Invocation(input: .bytes(
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF],
        ))
        #expect(ParsedCommandLine.parse(["--bytes", "01 23,45 67 89 ab cd ef AB,CD EF"]) == .run(expected))
    }

    @Test func statsAndFeaturesFlags() {
        let parsed = ParsedCommandLine.parse(["--stats", "--features", "arm64e", "0x1"])
        let expected = Invocation(input: .word(1), features: .arm64e, stats: true)
        #expect(parsed == .run(expected))
    }

    @Test func valueFlagsRepeatLastWins() {
        let parsed = ParsedCommandLine.parse(["--color", "always", "--color", "never", "0x0"])
        #expect(parsed == .run(Invocation(input: .word(0), color: .never)))
        let arches = ParsedCommandLine.parse(["--arch", "arm64", "--arch", "arm64e", "f"])
        #expect(arches == .run(Invocation(input: .file(path: "f"), arch: .arm64e)))
    }

    @Test func missingValueErrors() {
        #expect(ParsedCommandLine.parse(["--arch"]) == .usageError("--arch needs a value (arm64 or arm64e)"))
        #expect(ParsedCommandLine.parse(["--features"]) == .usageError("--features needs a value (arm64e)"))
        #expect(ParsedCommandLine.parse(["--color"]) == .usageError("--color needs a value (auto, always, or never)"))
        #expect(ParsedCommandLine.parse(["--bytes"]) == .usageError("--bytes needs a hex byte string (e.g. \"1f 20 03 d5\")"))
    }

    @Test func unknownValueErrors() {
        #expect(ParsedCommandLine.parse(["--arch", "x86_64"])
            == .usageError("unknown architecture 'x86_64' (expected arm64 or arm64e)"))
        #expect(ParsedCommandLine.parse(["--features", "sve"])
            == .usageError("unknown feature set 'sve' (expected arm64e)"))
        #expect(ParsedCommandLine.parse(["--color", "rainbow"])
            == .usageError("unknown color mode 'rainbow' (expected auto, always, or never)"))
    }

    @Test func unknownOptionError() {
        #expect(ParsedCommandLine.parse(["-x", "file"]) == .usageError("unknown option '-x'"))
    }

    @Test func inputCountErrors() {
        #expect(ParsedCommandLine.parse(["a", "b"]) == .usageError("more than one input ('a' and 'b')"))
        #expect(ParsedCommandLine.parse([]) == .usageError("no input (a file path, a 0x-prefixed word, or --bytes)"))
        #expect(ParsedCommandLine.parse(["--bytes", "1f", "also-a-file"])
            == .usageError("--bytes and a positional input are mutually exclusive"))
    }

    @Test func malformedWordErrors() {
        for bad in ["0x123456789", "0x", "0xzz"] {
            #expect(ParsedCommandLine.parse([bad])
                == .usageError("'\(bad)' is not a 32-bit instruction word (0x + 1...8 hex digits)"))
        }
    }

    @Test func malformedByteStringErrors() {
        for bad in ["1f 2", "xyz", "", "1f;20"] {
            #expect(ParsedCommandLine.parse(["--bytes", bad])
                == .usageError("--bytes wants pairs of hex digits separated by spaces or commas, got '\(bad)'"))
        }
    }

    @Test func featuresRejectedForFiles() {
        #expect(ParsedCommandLine.parse(["--features", "arm64e", "some/file"])
            == .usageError("--features applies to direct decode; use --arch to select a Mach-O slice"))
    }

    @Test func semanticsRejectedWithStats() {
        #expect(ParsedCommandLine.parse(["--stats", "--semantics", "0x0"])
            == .usageError("--semantics has no effect on --stats output"))
    }

    @Test func parseWordGrammar() {
        #expect(ParsedCommandLine.parseWord("0xffffffff") == 0xFFFF_FFFF)
        #expect(ParsedCommandLine.parseWord("0x0") == 0)
        #expect(ParsedCommandLine.parseWord("0x") == nil)
        #expect(ParsedCommandLine.parseWord("0x123456789") == nil)
        #expect(ParsedCommandLine.parseWord("0xgg") == nil)
    }

    @Test func parseByteStringGrammar() {
        #expect(ParsedCommandLine.parseByteString("00ff") == [0x00, 0xFF])
        #expect(ParsedCommandLine.parseByteString("AA, bb cc") == [0xAA, 0xBB, 0xCC])
        #expect(ParsedCommandLine.parseByteString("a") == nil)
        #expect(ParsedCommandLine.parseByteString("") == nil)
        #expect(ParsedCommandLine.parseByteString("0x1f") == nil)
    }

    @Test func directDecodeFeaturesPrecedence() {
        let explicit = Invocation(input: .word(0), arch: .arm64, features: .arm64e)
        #expect(explicit.directDecodeFeatures == .arm64e)
        let viaArch = Invocation(input: .word(0), arch: .arm64e)
        #expect(viaArch.directDecodeFeatures == .arm64e)
        let plain = Invocation(input: .word(0))
        #expect(plain.directDecodeFeatures == [])
    }
}

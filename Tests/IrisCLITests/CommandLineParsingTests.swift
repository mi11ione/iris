// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates argv parsing under the verb model: verb dispatch (explicit
/// word and inferred-from-shape), the verb-vs-filename edge, each verb's
/// accepted flag set with the unknown-option error for anything outside
/// it, the word/byte-string input grammars, and the global help/version.
@Suite("Command-line parsing")
struct CommandLineParsingTests {
    // MARK: Globals

    @Test func bareInvocationPrintsTopLevelHelp() {
        #expect(ParsedCommandLine.parse([]) == .help(nil))
    }

    @Test func helpFlagWinsAnywhere() {
        #expect(ParsedCommandLine.parse(["--help"]) == .help(nil))
        #expect(ParsedCommandLine.parse(["-h"]) == .help(nil))
        #expect(ParsedCommandLine.parse(["some/file", "--help", "--json"]) == .help(nil))
    }

    @Test func helpAfterAVerbShowsThatVerbsHelp() {
        #expect(ParsedCommandLine.parse(["stats", "--help"]) == .help(.stats))
        #expect(ParsedCommandLine.parse(["decode", "-h"]) == .help(.decode))
        #expect(ParsedCommandLine.parse(["disasm", "--help"]) == .help(.disasm))
        #expect(ParsedCommandLine.parse(["functions", "--help"]) == .help(.functions))
        // The verb is found even behind a leading flag.
        #expect(ParsedCommandLine.parse(["--json", "stats", "--help"]) == .help(.stats))
    }

    @Test func versionFlagWinsAnywhere() {
        #expect(ParsedCommandLine.parse(["--version"]) == .version)
        #expect(ParsedCommandLine.parse(["some/file", "--version", "--json"]) == .version)
        #expect(ParsedCommandLine.parse(["stats", "--version"]) == .version)
    }

    // MARK: Verb dispatch

    @Test func explicitVerbWords() {
        #expect(ParsedCommandLine.parse(["disasm", "a/binary"]) == .run(Invocation(verb: .disasm, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["stats", "a/binary"]) == .run(Invocation(verb: .stats, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["functions", "a/binary"]) == .run(Invocation(verb: .functions, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["decode", "0xd503201f"]) == .run(Invocation(verb: .decode, input: .word(0xD503_201F))))
    }

    @Test func defaultVerbIsDisasmForAPath() {
        // No verb word, a path positional infers disasm.
        #expect(ParsedCommandLine.parse(["a/binary"]) == .run(Invocation(verb: .disasm, input: .file(path: "a/binary"))))
    }

    @Test func decodeIsInferredForWordAndBytes() {
        #expect(ParsedCommandLine.parse(["0xd503201f"]) == .run(Invocation(verb: .decode, input: .word(0xD503_201F))))
        #expect(ParsedCommandLine.parse(["0X1F2"]) == .run(Invocation(verb: .decode, input: .word(0x1F2))))
        let bytes = Invocation(verb: .decode, input: .bytes([0x1F, 0x20, 0x03, 0xD5]))
        #expect(ParsedCommandLine.parse(["--bytes", "1f 20 03 d5"]) == .run(bytes))
    }

    @Test func verbBehindALeadingFlagIsStillFound() {
        // The verb word need not be argv[0]; a leading flag does not hide it.
        let parsed = ParsedCommandLine.parse(["--color", "never", "functions", "a/binary"])
        let expected = Invocation(verb: .functions, input: .file(path: "a/binary"), color: .never)
        #expect(parsed == .run(expected))
    }

    @Test func aFilenameThatIsAVerbWordReachesViaTheExplicitVerb() {
        // 'iris disasm stats' disassembles a file named 'stats': the first
        // bare token (disasm) is the verb, the next bare token is the path.
        let parsed = ParsedCommandLine.parse(["disasm", "stats"])
        #expect(parsed == .run(Invocation(verb: .disasm, input: .file(path: "stats"))))
    }

    @Test func aPathBeginningWithDotSlashIsNotAVerb() {
        // './stats' is a path, never the stats verb (it is not a bare verb
        // word), so it infers disasm with that path.
        #expect(ParsedCommandLine.parse(["./stats"]) == .run(Invocation(verb: .disasm, input: .file(path: "./stats"))))
    }

    // MARK: Per-verb flag sets

    @Test func disasmAcceptsItsFullFlagSet() {
        let parsed = ParsedCommandLine.parse([
            "disasm", "--arch", "arm64e", "--json", "--semantics", "--quiet", "--color", "never", "a/binary",
        ])
        let expected = Invocation(
            verb: .disasm, input: .file(path: "a/binary"),
            arch: .arm64e, json: true, semantics: true, color: .never, quiet: true,
        )
        #expect(parsed == .run(expected))
    }

    @Test func decodeAcceptsItsFullFlagSet() {
        let parsed = ParsedCommandLine.parse(["decode", "--features", "arm64e", "--semantics", "--json", "--color", "never", "0x1"])
        let expected = Invocation(
            verb: .decode, input: .word(1),
            features: .arm64e, json: true, semantics: true, color: .never,
        )
        #expect(parsed == .run(expected))
    }

    @Test func statsAcceptsItsFlagSet() {
        let parsed = ParsedCommandLine.parse(["stats", "--arch", "arm64", "--json", "--color", "always", "--quiet", "f"])
        let expected = Invocation(verb: .stats, input: .file(path: "f"), arch: .arm64, json: true, color: .always, quiet: true)
        #expect(parsed == .run(expected))
    }

    @Test func functionsAcceptsItsFlagSet() {
        let parsed = ParsedCommandLine.parse(["functions", "--json", "a/binary"])
        let expected = Invocation(verb: .functions, input: .file(path: "a/binary"), json: true)
        #expect(parsed == .run(expected))
    }

    // MARK: Per-verb unknown-option errors (the no-op class is gone)

    @Test func semanticsIsRejectedByStats() {
        // The headline of the restructure: stats has no --semantics (it is a
        // summary, not a listing), so the flat model's no-op is now a clean
        // usage error scoped to the verb.
        #expect(ParsedCommandLine.parse(["stats", "--semantics", "f"])
            == .usageError("iris stats: error: unknown option '--semantics'"))
    }

    @Test func semanticsIsRejectedByFunctions() {
        #expect(ParsedCommandLine.parse(["functions", "--semantics", "f"])
            == .usageError("iris functions: error: unknown option '--semantics'"))
    }

    @Test func featuresIsRejectedByEveryFileVerb() {
        for verb in ["disasm", "stats", "functions"] {
            #expect(ParsedCommandLine.parse([verb, "--features", "arm64e", "f"])
                == .usageError("iris \(verb): error: unknown option '--features'"))
        }
    }

    @Test func archIsRejectedByDecode() {
        #expect(ParsedCommandLine.parse(["decode", "--arch", "arm64", "0x1"])
            == .usageError("iris decode: error: unknown option '--arch'"))
    }

    @Test func quietIsRejectedByDecode() {
        #expect(ParsedCommandLine.parse(["decode", "--quiet", "0x1"])
            == .usageError("iris decode: error: unknown option '--quiet'"))
    }

    @Test func bytesOnAFileVerbRedirectsToDecode() {
        // --bytes is decode's input carrier. A file verb redirects to decode
        // rather than dead-ending at "unknown option", matching the raw-word
        // positional guidance.
        for verb in ["disasm", "stats", "functions"] {
            #expect(ParsedCommandLine.parse([verb, "--bytes", "1f 20 03 d5"])
                == .usageError("iris \(verb): error: --bytes carries raw words; use 'iris decode --bytes …'"))
        }
    }

    @Test func unknownFlagIsScopedToTheInferredVerb() {
        // No explicit verb word: the error scope is plain `iris:`.
        #expect(ParsedCommandLine.parse(["-x", "file"]) == .usageError("iris: error: unknown option '-x'"))
        #expect(ParsedCommandLine.parse(["--bogus", "0x1"]) == .usageError("iris: error: unknown option '--bogus'"))
    }

    // MARK: Input shape vs verb

    @Test func aFileVerbRejectsARawWord() {
        #expect(ParsedCommandLine.parse(["stats", "0xd503201f"])
            == .usageError("iris stats: error: '0xd503201f' is a raw word; use 'iris decode 0xd503201f'"))
    }

    @Test func decodeRejectsAPath() {
        #expect(ParsedCommandLine.parse(["decode", "some/file"])
            == .usageError("iris decode: error: 'some/file' is not a 0x-prefixed word; use 'iris disasm some/file' for a file"))
    }

    // MARK: Value flags

    @Test func bytesInputAcceptsEverySeparatorAndCase() {
        let expected = Invocation(verb: .decode, input: .bytes([0x1F, 0x20, 0x03, 0xD5]))
        #expect(ParsedCommandLine.parse(["--bytes", "1f,20,03,d5"]) == .run(expected))
        #expect(ParsedCommandLine.parse(["--bytes", "1F2003D5"]) == .run(expected))
        let wide = Invocation(verb: .decode, input: .bytes(
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xAB, 0xCD, 0xEF],
        ))
        #expect(ParsedCommandLine.parse(["--bytes", "01 23,45 67 89 ab cd ef AB,CD EF"]) == .run(wide))
    }

    @Test func valueFlagsRepeatLastWins() {
        #expect(ParsedCommandLine.parse(["decode", "--color", "always", "--color", "never", "0x0"])
            == .run(Invocation(verb: .decode, input: .word(0), color: .never)))
        #expect(ParsedCommandLine.parse(["--arch", "arm64", "--arch", "arm64e", "f"])
            == .run(Invocation(verb: .disasm, input: .file(path: "f"), arch: .arm64e)))
    }

    @Test func missingValueErrors() {
        #expect(ParsedCommandLine.parse(["disasm", "--arch"]) == .usageError("iris disasm: error: --arch needs a value (arm64 or arm64e)"))
        #expect(ParsedCommandLine.parse(["decode", "--features"]) == .usageError("iris decode: error: --features needs a value (arm64e)"))
        #expect(ParsedCommandLine.parse(["disasm", "--color"]) == .usageError("iris disasm: error: --color needs a value (auto, always, or never)"))
        #expect(ParsedCommandLine.parse(["--bytes"]) == .usageError("iris: error: --bytes needs a hex byte string (e.g. \"1f 20 03 d5\")"))
    }

    @Test func unknownValueErrors() {
        #expect(ParsedCommandLine.parse(["disasm", "--arch", "x86_64", "f"])
            == .usageError("iris disasm: error: unknown architecture 'x86_64' (expected arm64 or arm64e)"))
        #expect(ParsedCommandLine.parse(["decode", "--features", "sve", "0x1"])
            == .usageError("iris decode: error: unknown feature set 'sve' (expected arm64e)"))
        #expect(ParsedCommandLine.parse(["disasm", "--color", "rainbow", "f"])
            == .usageError("iris disasm: error: unknown color mode 'rainbow' (expected auto, always, or never)"))
    }

    // MARK: Input-count errors

    @Test func inputCountErrors() {
        #expect(ParsedCommandLine.parse(["disasm", "a", "b"]) == .usageError("iris disasm: error: more than one input ('a' and 'b')"))
        #expect(ParsedCommandLine.parse(["stats"]) == .usageError("iris stats: error: no input (a Mach-O file path)"))
        #expect(ParsedCommandLine.parse(["decode"]) == .usageError("iris decode: error: no input (a 0x-prefixed word, or --bytes)"))
        // --bytes infers decode, but inferred (verb-less) errors carry the
        // plain `iris:` scope, not `iris decode:`.
        #expect(ParsedCommandLine.parse(["--bytes", "1f", "also-a-file"])
            == .usageError("iris: error: --bytes and a positional input are mutually exclusive"))
    }

    @Test func malformedWordErrors() {
        for bad in ["0x123456789", "0x", "0xzz"] {
            #expect(ParsedCommandLine.parse(["decode", bad])
                == .usageError("iris decode: error: '\(bad)' is not a 32-bit instruction word (0x + 1...8 hex digits)"))
        }
    }

    @Test func malformedByteStringErrors() {
        for bad in ["1f 2", "xyz", "", "1f;20"] {
            #expect(ParsedCommandLine.parse(["--bytes", bad])
                == .usageError("iris: error: --bytes wants pairs of hex digits separated by spaces or commas, got '\(bad)'"))
        }
    }

    // MARK: Verb properties

    @Test func verbFlagAcceptance() {
        #expect(Verb.disasm.accepts("--arch") && Verb.disasm.accepts("--semantics") && Verb.disasm.accepts("--quiet"))
        #expect(!Verb.disasm.accepts("--features") && !Verb.disasm.accepts("--bytes"))
        #expect(Verb.decode.accepts("--features") && Verb.decode.accepts("--semantics") && Verb.decode.accepts("--bytes"))
        #expect(!Verb.decode.accepts("--arch") && !Verb.decode.accepts("--quiet"))
        #expect(Verb.stats.accepts("--arch") && Verb.stats.accepts("--quiet"))
        #expect(!Verb.stats.accepts("--semantics") && !Verb.stats.accepts("--features"))
        #expect(Verb.functions.accepts("--json") && Verb.functions.accepts("--color"))
        #expect(!Verb.functions.accepts("--semantics"))
        #expect(!Verb.disasm.accepts("--nonexistent"))
    }

    @Test func verbReadsFileDiscriminates() {
        #expect(Verb.disasm.readsFile && Verb.stats.readsFile && Verb.functions.readsFile)
        #expect(!Verb.decode.readsFile)
    }

    @Test func inputIsFileDiscriminates() {
        #expect(Invocation.Input.file(path: "f").isFile)
        #expect(!Invocation.Input.word(0).isFile)
        #expect(!Invocation.Input.bytes([0]).isFile)
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
        let explicit = Invocation(verb: .decode, input: .word(0), features: .arm64e)
        #expect(explicit.directDecodeFeatures == .arm64e)
        let plain = Invocation(verb: .decode, input: .word(0))
        #expect(plain.directDecodeFeatures == [])
    }
}

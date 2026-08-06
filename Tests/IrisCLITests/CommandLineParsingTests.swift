// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris
import IrisCLICore
import Testing

/// Validates argv parsing.
@Suite("Command-line parsing")
struct CommandLineParsingTests {
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
        #expect(ParsedCommandLine.parse(["--json", "stats", "--help"]) == .help(.stats))
    }

    @Test func versionFlagWinsAnywhere() {
        #expect(ParsedCommandLine.parse(["--version"]) == .version)
        #expect(ParsedCommandLine.parse(["some/file", "--version", "--json"]) == .version)
        #expect(ParsedCommandLine.parse(["stats", "--version"]) == .version)
    }

    @Test func explicitVerbWords() {
        #expect(ParsedCommandLine.parse(["disasm", "a/binary"]) == .run(Invocation(verb: .disasm, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["stats", "a/binary"]) == .run(Invocation(verb: .stats, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["functions", "a/binary"]) == .run(Invocation(verb: .functions, input: .file(path: "a/binary"))))
        #expect(ParsedCommandLine.parse(["decode", "0xd503201f"]) == .run(Invocation(verb: .decode, input: .word(0xD503_201F))))
    }

    @Test func defaultVerbIsDisasmForAPath() {
        #expect(ParsedCommandLine.parse(["a/binary"]) == .run(Invocation(verb: .disasm, input: .file(path: "a/binary"))))
    }

    @Test func decodeIsInferredForWordAndBytes() {
        #expect(ParsedCommandLine.parse(["0xd503201f"]) == .run(Invocation(verb: .decode, input: .word(0xD503_201F))))
        #expect(ParsedCommandLine.parse(["0X1F2"]) == .run(Invocation(verb: .decode, input: .word(0x1F2))))
        let bytes = Invocation(verb: .decode, input: .bytes([0x1F, 0x20, 0x03, 0xD5]))
        #expect(ParsedCommandLine.parse(["--bytes", "1f 20 03 d5"]) == .run(bytes))
    }

    @Test func verbBehindALeadingFlagIsStillFound() {
        let parsed = ParsedCommandLine.parse(["--color", "never", "functions", "a/binary"])
        let expected = Invocation(verb: .functions, input: .file(path: "a/binary"), color: .never)
        #expect(parsed == .run(expected))
    }

    @Test func aFilenameThatIsAVerbWordReachesViaTheExplicitVerb() {
        let parsed = ParsedCommandLine.parse(["disasm", "stats"])
        #expect(parsed == .run(Invocation(verb: .disasm, input: .file(path: "stats"))))
    }

    @Test func aPathBeginningWithDotSlashIsNotAVerb() {
        #expect(ParsedCommandLine.parse(["./stats"]) == .run(Invocation(verb: .disasm, input: .file(path: "./stats"))))
    }

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

    @Test func semanticsIsRejectedByStats() {
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
        for verb in ["disasm", "stats", "functions"] {
            #expect(ParsedCommandLine.parse([verb, "--bytes", "1f 20 03 d5"])
                == .usageError("iris \(verb): error: --bytes carries raw words; use 'iris decode --bytes …'"))
        }
    }

    @Test func unknownFlagIsScopedToTheInferredVerb() {
        #expect(ParsedCommandLine.parse(["-x", "file"]) == .usageError("iris: error: unknown option '-x'"))
        #expect(ParsedCommandLine.parse(["--bogus", "0x1"]) == .usageError("iris: error: unknown option '--bogus'"))
    }

    @Test func aFileVerbRejectsARawWord() {
        #expect(ParsedCommandLine.parse(["stats", "0xd503201f"])
            == .usageError("iris stats: error: '0xd503201f' is a raw word; use 'iris decode 0xd503201f'"))
    }

    @Test func decodeRejectsAPath() {
        #expect(ParsedCommandLine.parse(["decode", "some/file"])
            == .usageError("iris decode: error: 'some/file' is not a 0x-prefixed word; use 'iris disasm some/file' for a file"))
    }

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

    @Test func inputCountErrors() {
        #expect(ParsedCommandLine.parse(["disasm", "a", "b"]) == .usageError("iris disasm: error: more than one input ('a' and 'b')"))
        #expect(ParsedCommandLine.parse(["stats"]) == .usageError("iris stats: error: no input (a Mach-O file path)"))
        #expect(ParsedCommandLine.parse(["decode"]) == .usageError("iris decode: error: no input (a 0x-prefixed word, or --bytes)"))
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

    @Test func slimRidesWhereJSONIs() {
        #expect(Verb.disasm.accepts("--slim") && Verb.decode.accepts("--slim")
            && Verb.stats.accepts("--slim") && Verb.functions.accepts("--slim"))
        let parsed = ParsedCommandLine.parse(["functions", "--json", "--slim", "a/binary"])
        #expect(parsed == .run(Invocation(verb: .functions, input: .file(path: "a/binary"), json: true, slim: true)))
        let decodeSlim = ParsedCommandLine.parse(["decode", "--json", "--slim", "0x1"])
        #expect(decodeSlim == .run(Invocation(verb: .decode, input: .word(1), json: true, slim: true)))
    }

    @Test func slimWithoutJSONIsAUsageError() {
        #expect(ParsedCommandLine.parse(["disasm", "--slim", "f"])
            == .usageError("iris disasm: error: --slim shapes --json output; add --json (or drop --slim)"))
        #expect(ParsedCommandLine.parse(["--slim", "f"])
            == .usageError("iris: error: --slim shapes --json output; add --json (or drop --slim)"))
    }

    @Test func disasmAcceptsFunctionAndRange() {
        #expect(Verb.disasm.accepts("--function") && Verb.disasm.accepts("--range"))
        #expect(!Verb.stats.accepts("--function") && !Verb.functions.accepts("--range"))
        let byName = ParsedCommandLine.parse(["disasm", "--function", "_main", "f"])
        #expect(byName == .run(Invocation(verb: .disasm, input: .file(path: "f"), function: "_main")))
        let byRange = ParsedCommandLine.parse(["disasm", "--range", "0x1080:0x1170", "f"])
        let range = Invocation.AddressRange(start: 0x1080, end: 0x1170)
        #expect(byRange == .run(Invocation(verb: .disasm, input: .file(path: "f"), range: range)))
    }

    @Test func rangeAcceptsHexAndDecimal() {
        let hex = ParsedCommandLine.parse(["disasm", "--range", "0x10:0x20", "f"])
        #expect(hex == .run(Invocation(verb: .disasm, input: .file(path: "f"), range: .init(start: 0x10, end: 0x20))))
        let decimal = ParsedCommandLine.parse(["disasm", "--range", "16:32", "f"])
        #expect(decimal == .run(Invocation(verb: .disasm, input: .file(path: "f"), range: .init(start: 16, end: 32))))
    }

    @Test func functionAndRangeAreRejectedByNonDisasmVerbs() {
        for verb in ["stats", "functions"] {
            #expect(ParsedCommandLine.parse([verb, "--function", "_main", "f"])
                == .usageError("iris \(verb): error: unknown option '--function'"))
            #expect(ParsedCommandLine.parse([verb, "--range", "0x1:0x2", "f"])
                == .usageError("iris \(verb): error: unknown option '--range'"))
        }
        #expect(ParsedCommandLine.parse(["decode", "--function", "_main", "0x1"])
            == .usageError("iris decode: error: unknown option '--function'"))
    }

    @Test func malformedRangeErrors() {
        for bad in ["notarange", "", "0x10", "0x10:0x20:0x30", "0x20:0x10", "0x10:", ":0x20", "0xzz:0x10"] {
            #expect(ParsedCommandLine.parse(["disasm", "--range", bad, "f"])
                == .usageError("iris disasm: error: --range wants start:end as 0x-hex or decimal with start < end, got '\(bad)'"))
        }
    }

    @Test func missingFunctionAndRangeValuesError() {
        #expect(ParsedCommandLine.parse(["disasm", "--function"])
            == .usageError("iris disasm: error: --function needs a function name"))
        #expect(ParsedCommandLine.parse(["disasm", "--range"])
            == .usageError("iris disasm: error: --range needs a value (start:end, e.g. 0x1080:0x1170)"))
    }

    @Test func functionAndRangeTogetherAreAUsageError() {
        #expect(ParsedCommandLine.parse(["disasm", "--function", "_main", "--range", "0x1:0x2", "f"])
            == .usageError("iris disasm: error: --function and --range both scope the output; use one"))
    }

    @Test func functionNameIsSteppedOverDuringVerbInference() {
        let parsed = ParsedCommandLine.parse(["--function", "_main", "a/binary"])
        #expect(parsed == .run(Invocation(verb: .disasm, input: .file(path: "a/binary"), function: "_main")))
    }

    @Test func decodeTakesABaseAddress() {
        #expect(Verb.decode.accepts("--at"))
        #expect(!Verb.disasm.accepts("--at") && !Verb.stats.accepts("--at") && !Verb.functions.accepts("--at"))
        let hex = ParsedCommandLine.parse(["decode", "--at", "0xfffffe0007b3c000", "--bytes", "0d fe ff 17"])
        #expect(hex == .run(Invocation(
            verb: .decode, input: .bytes([0x0D, 0xFE, 0xFF, 0x17]), address: 0xFFFF_FE00_07B3_C000,
        )))
        let decimal = ParsedCommandLine.parse(["decode", "--at", "4096", "0xd503201f"])
        #expect(decimal == .run(Invocation(verb: .decode, input: .word(0xD503_201F), address: 4096)))
        #expect(ParsedCommandLine.parse(["0xd503201f"])
            == .run(Invocation(verb: .decode, input: .word(0xD503_201F), address: 0)))
    }

    @Test func baseAddressIsLastWinsAndSteppedOverDuringVerbInference() {
        let inferred = ParsedCommandLine.parse(["--at", "0x1000", "--bytes", "1f 20 03 d5"])
        #expect(inferred == .run(Invocation(
            verb: .decode, input: .bytes([0x1F, 0x20, 0x03, 0xD5]), address: 0x1000,
        )))
        let lastWins = ParsedCommandLine.parse(["--at", "0x1000", "--at", "0x2000", "0x1"])
        #expect(lastWins == .run(Invocation(verb: .decode, input: .word(1), address: 0x2000)))
    }

    @Test func malformedBaseAddressErrors() {
        for bad in ["", "0x", "0xzz", "notanaddress", "-1", "0x1_0", "0x10:0x20"] {
            #expect(ParsedCommandLine.parse(["decode", "--at", bad, "0x1"])
                == .usageError("iris decode: error: --at wants a base address as 0x-hex or decimal, got '\(bad)'"))
        }
    }

    @Test func missingBaseAddressValueErrors() {
        #expect(ParsedCommandLine.parse(["decode", "--at"])
            == .usageError("iris decode: error: --at needs a value (a base address, 0x-hex or decimal, e.g. 0xfffffe0007b3c000)"))
    }

    @Test func fileVerbsRejectABaseAddress() {
        for verb in ["disasm", "stats", "functions"] {
            #expect(ParsedCommandLine.parse([verb, "--at", "0x1000", "f"])
                == .usageError("iris \(verb): error: --at bases raw words; a Mach-O file carries its own addresses"))
        }
        #expect(ParsedCommandLine.parse(["--at", "0x1000", "a/binary"])
            == .usageError("iris: error: --at bases raw words; a Mach-O file carries its own addresses"))
    }

    @Test func parseAddressRangeGrammar() {
        #expect(ParsedCommandLine.parseAddressRange("0x10:0x20") == .init(start: 0x10, end: 0x20))
        #expect(ParsedCommandLine.parseAddressRange("0:1") == .init(start: 0, end: 1))
        #expect(ParsedCommandLine.parseAddressRange("0x10") == nil)
        #expect(ParsedCommandLine.parseAddressRange("0x20:0x10") == nil)
        #expect(ParsedCommandLine.parseAddressRange("a:b") == nil)
        #expect(ParsedCommandLine.parseAddressRange("") == nil)
        #expect(ParsedCommandLine.parseAddress("0xff") == 0xFF)
        #expect(ParsedCommandLine.parseAddress("255") == 255)
        #expect(ParsedCommandLine.parseAddress("0x") == nil)
        #expect(ParsedCommandLine.parseAddress("zz") == nil)
    }
}

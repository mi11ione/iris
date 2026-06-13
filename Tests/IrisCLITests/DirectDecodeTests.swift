// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates the `decode` verb (`iris 0x<word>`, `iris --bytes`, and the
/// explicit `iris decode …`): little-endian word assembly, multi-word
/// sequences, and how its flags (`--features`, `--semantics`, `--json`)
/// compose with the input. `--arch` belongs to the file verbs, not decode.
@Suite("Decode verb")
struct DirectDecodeTests {
    @Test func singleWordDecodes() {
        let run = runCLI(["0xd503201f"])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == "0: d503201f  nop\n")
        #expect(run.stderr.isEmpty)
    }

    @Test func shortWordIsZeroExtended() {
        // 0x91421 zero-extends to 0x00091421 (reserved-tier UNDEFINED);
        // the word column still shows all 8 digits.
        let run = runCLI(["0x91421"])
        #expect(run.stdout == "0: 00091421  .long 0x91421 ; undefined\n")
    }

    @Test func byteSequenceDecodesAsWords() {
        let run = runCLI(["--bytes", "1f 20 03 d5 c0 03 5f d6"])
        #expect(run.stdout == "0: d503201f  nop\n4: d65f03c0  ret\n")
    }

    @Test func wordAndBytesAgree() {
        let word = runCLI(["0xd65f03c0"])
        let bytes = runCLI(["--bytes", "c0 03 5f d6"])
        #expect(word.stdout == bytes.stdout)
    }

    @Test func featuresUnlockArm64EOnlyEncodings() {
        let plain = runCLI(["0xf8200420"])
        #expect(plain.stdout == "0: f8200420  .long 0xf8200420 ; undefined\n")
        let withFeatures = runCLI(["--features", "arm64e", "0xf8200420"])
        #expect(withFeatures.stdout == "0: f8200420  ldraa x0, [x1]\n")
    }

    @Test func archIsRejectedByDecode() {
        // --arch selects a Mach-O slice and belongs to the file verbs;
        // decode unlocks extensions with --features instead.
        let explicit = runCLI(["decode", "--arch", "arm64", "0xf8200420"])
        #expect(explicit.status == CLI.exitUsage)
        #expect(explicit.stderr.contains("iris decode: error: unknown option '--arch'"))
        // Inferred decode (0x token, no verb word) scopes the error to
        // plain `iris:`.
        let inferred = runCLI(["--arch", "arm64e", "0xf8200420"])
        #expect(inferred.status == CLI.exitUsage)
        #expect(inferred.stderr.contains("iris: error: unknown option '--arch'"))
    }

    @Test func explicitDecodeVerbAndFeaturesAgree() {
        let inferred = runCLI(["--features", "arm64e", "0xf8200420"])
        let explicit = runCLI(["decode", "--features", "arm64e", "0xf8200420"])
        #expect(explicit.stdout == inferred.stdout)
        #expect(explicit.stdout == "0: f8200420  ldraa x0, [x1]\n")
    }

    @Test func semanticsAnnotatesDirectLines() {
        let run = runCLI(["--semantics", "0x91000421"])
        #expect(run.stdout == "0: 91000421  add x1, x1, #1                              ; reads=x1 writes=x1\n")
    }

    @Test func jsonComposesWithDirectDecode() {
        let run = runCLI(["--json", "0xd503201f"])
        #expect(run.stdout.hasPrefix("{\"schemaVersion\":1,\"kind\":\"instruction\",\"address\":\"0x0\""))
        #expect(run.stdout.contains("\"mnemonic\":\"nop\""))
    }

    @Test func addressColumnGrowsWithSequenceLength() {
        // 5 words: addresses 0..0x10, width 2.
        let run = runCLI(["--bytes", "1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 c0 03 5f d6"])
        #expect(run.stdout.hasPrefix("00: d503201f  nop\n"))
        #expect(run.stdout.contains("\n10: d65f03c0  ret\n"))
    }

    @Test func longestInputsStayAligned() {
        let run = runCLI(["--bytes", "ff ff ff ff 00 00 00 04"])
        // Both lines render the 8-digit word column then two spaces.
        for line in run.stdout.split(separator: "\n") {
            #expect(line.count > 13)
            #expect(line.prefix(3).hasSuffix(": "))
        }
    }
}

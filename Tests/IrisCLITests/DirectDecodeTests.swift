// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates the `decode` verb.
@Suite("Decode verb")
struct DirectDecodeTests {
    @Test func singleWordDecodes() {
        let run = runCLI(["0xd503201f"])
        #expect(run.status == CLI.exitSuccess)
        #expect(run.stdout == "0: d503201f  nop\n")
        #expect(run.stderr.isEmpty)
    }

    @Test func shortWordIsZeroExtended() {
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
        let explicit = runCLI(["decode", "--arch", "arm64", "0xf8200420"])
        #expect(explicit.status == CLI.exitUsage)
        #expect(explicit.stderr.contains("iris decode: error: unknown option '--arch'"))
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
        let run = runCLI(["--bytes", "1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 1f 20 03 d5 c0 03 5f d6"])
        #expect(run.stdout.hasPrefix("00: d503201f  nop\n"))
        #expect(run.stdout.contains("\n10: d65f03c0  ret\n"))
    }

    @Test func baseAddressResolvesRelativeBranches() {
        let atZero = runCLI(["--bytes", "0d fe ff 17"])
        #expect(atZero.stdout == "0: 17fffe0d  b 0xfffffffffffff834\n")
        let based = runCLI(["--bytes", "0d fe ff 17", "--at", "0xfffffe0007b3c000"])
        #expect(based.status == CLI.exitSuccess)
        #expect(based.stdout == "fffffe0007b3c000: 17fffe0d  b 0xfffffe0007b3b834\n")
    }

    @Test func baseAddressCarriesEveryWordAndTheJSONAddress() {
        let listing = runCLI(["decode", "--at", "0xfffffe0007b3c000", "--bytes", "1f 20 03 d5 c0 03 5f d6"])
        #expect(listing.stdout == "fffffe0007b3c000: d503201f  nop\nfffffe0007b3c004: d65f03c0  ret\n")
        let decimal = runCLI(["--bytes", "1f 20 03 d5", "--at", "4096"])
        #expect(decimal.stdout == "1000: d503201f  nop\n")
        let json = runCLI(["--json", "--at", "0x1000", "0xd503201f"])
        #expect(json.stdout.contains("\"address\":\"0x1000\""))
    }

    @Test func longestInputsStayAligned() {
        let run = runCLI(["--bytes", "ff ff ff ff 00 00 00 04"])
        for line in run.stdout.split(separator: "\n") {
            #expect(line.count > 13)
            #expect(line.prefix(3).hasSuffix(": "))
        }
    }
}

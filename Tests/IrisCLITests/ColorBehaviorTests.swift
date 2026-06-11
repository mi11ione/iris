// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import IrisCLICore
import Testing

/// Validates TTY-aware color: `auto` colors only on a terminal, escapes
/// never leak into piped output, columns stay aligned because padding is
/// computed on plain text before colorization.
@Suite("Color behavior")
struct ColorBehaviorTests {
    /// The ANSI escape introducer.
    static let escape = Character("\u{1B}")

    @Test func autoWithoutTTYEmitsNoEscapes() {
        let run = runCLI(["--color", "auto", cliFixturePath("hello-arm64")], tty: false)
        #expect(run.status == CLI.exitSuccess)
        #expect(!run.stdout.contains(Self.escape))
    }

    @Test func autoWithTTYColors() {
        let run = runCLI(["--color", "auto", "0xd503201f"], tty: true)
        #expect(run.stdout.contains(Self.escape))
    }

    @Test func defaultModeIsAuto() {
        let piped = runCLI(["0xd503201f"], tty: false)
        #expect(!piped.stdout.contains(Self.escape))
        let terminal = runCLI(["0xd503201f"], tty: true)
        #expect(terminal.stdout.contains(Self.escape))
    }

    @Test func alwaysColorsEvenWhenPiped() {
        let run = runCLI(["--color", "always", "0xd503201f"], tty: false)
        #expect(run.stdout == "\u{1B}[2m0:\u{1B}[0m d503201f  \u{1B}[36mnop\u{1B}[0m\n")
    }

    @Test func neverStaysPlainOnTTY() {
        let run = runCLI(["--color", "never", "0xd503201f"], tty: true)
        #expect(run.stdout == "0: d503201f  nop\n")
    }

    @Test func coloredListingMatchesPlainAfterStrippingEscapes() {
        let plain = runCLI(["--color", "never", "--semantics", cliFixturePath("hello-arm64")])
        let colored = runCLI(["--color", "always", "--semantics", cliFixturePath("hello-arm64")])
        #expect(stripANSI(colored.stdout) == plain.stdout)
        #expect(colored.stdout != plain.stdout)
    }

    @Test func resolvedPolicyTruthTable() {
        #expect(ColorMode.auto.resolved(standardOutputIsTTY: true))
        #expect(!ColorMode.auto.resolved(standardOutputIsTTY: false))
        #expect(ColorMode.always.resolved(standardOutputIsTTY: false))
        #expect(ColorMode.always.resolved(standardOutputIsTTY: true))
        #expect(!ColorMode.never.resolved(standardOutputIsTTY: true))
        #expect(!ColorMode.never.resolved(standardOutputIsTTY: false))
    }

    @Test func paletteIsIdentityWhenDisabled() {
        let off = Palette(enabled: false)
        #expect(off.label("x") == "x")
        #expect(off.mnemonic("x") == "x")
        #expect(off.data("x") == "x")
        #expect(off.annotation("x") == "x")
        #expect(off.address("x") == "x")
    }

    @Test func paletteWrapsEachRoleDistinctly() {
        let on = Palette(enabled: true)
        #expect(on.label("x") == "\u{1B}[1mx\u{1B}[0m")
        #expect(on.mnemonic("x") == "\u{1B}[36mx\u{1B}[0m")
        #expect(on.data("x") == "\u{1B}[33mx\u{1B}[0m")
        #expect(on.annotation("x") == "\u{1B}[90mx\u{1B}[0m")
        #expect(on.address("x") == "\u{1B}[2mx\u{1B}[0m")
    }

    @Test func paletteNeverWrapsEmptyText() {
        let on = Palette(enabled: true)
        #expect(on.annotation("") == "")
        #expect(on.mnemonic("").isEmpty)
    }

    /// Remove ANSI SGR sequences (`ESC [ ... m`).
    func stripANSI(_ text: String) -> String {
        var out = ""
        var inEscape = false
        for character in text {
            if inEscape {
                inEscape = character != "m"
            } else if character == Self.escape {
                inEscape = true
            } else {
                out.append(character)
            }
        }
        return out
    }
}

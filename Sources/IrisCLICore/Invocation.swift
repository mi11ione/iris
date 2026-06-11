// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// One parsed `iris` invocation: the input plus every mode flag.
@frozen
public struct Invocation: Sendable, Equatable {
    /// What to disassemble.
    @frozen
    public enum Input: Sendable, Equatable {
        /// A Mach-O file (thin or fat).
        case file(path: String)
        /// One little-endian instruction word (`iris 0xd503201f`).
        case word(UInt32)
        /// A byte sequence decoded as little-endian words (`--bytes`).
        case bytes([UInt8])
    }

    public var input: Input
    /// `--arch`: slice selection for files; features alias for direct decode.
    public var arch: ArchSelection?
    /// `--features`: explicit decode features for the direct modes.
    public var features: Features?
    /// `--json`: NDJSON output.
    public var json: Bool
    /// `--semantics`: per-line semantic annotations.
    public var semantics: Bool
    /// `--stats`: census output instead of a listing.
    public var stats: Bool
    /// `--color` policy.
    public var color: ColorMode
    /// `--quiet`: suppress diagnostics on stderr.
    public var quiet: Bool

    public init(
        input: Input,
        arch: ArchSelection? = nil,
        features: Features? = nil,
        json: Bool = false,
        semantics: Bool = false,
        stats: Bool = false,
        color: ColorMode = .auto,
        quiet: Bool = false,
    ) {
        self.input = input
        self.arch = arch
        self.features = features
        self.json = json
        self.semantics = semantics
        self.stats = stats
        self.color = color
        self.quiet = quiet
    }

    /// The features a direct-decode input uses: explicit `--features`
    /// first, then the `--arch` alias, then plain ARM64.
    @inlinable
    public var directDecodeFeatures: Features {
        features ?? arch?.features ?? []
    }
}

/// Result of parsing argv (everything after the executable name).
@frozen
public enum ParsedCommandLine: Sendable, Equatable {
    /// A well-formed invocation.
    case run(Invocation)
    /// `--help` / `-h`.
    case help
    /// `--version`.
    case version
    /// A usage error with its message (exit code 1).
    case usageError(String)
}

public extension ParsedCommandLine {
    /// Parse argv. Flags may appear in any order around the single
    /// positional input; value flags repeat last-wins.
    static func parse(_ arguments: [String]) -> ParsedCommandLine {
        var positional: String?
        var bytesArgument: String?
        var arch: ArchSelection?
        var features: Features?
        var json = false
        var semantics = false
        var stats = false
        var color: ColorMode = .auto
        var quiet = false

        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            index += 1
            switch argument {
            case "--help", "-h":
                return .help
            case "--version":
                return .version
            case "--json":
                json = true
            case "--semantics":
                semantics = true
            case "--stats":
                stats = true
            case "--quiet":
                quiet = true
            case "--arch":
                guard index < arguments.count else {
                    return .usageError("--arch needs a value (arm64 or arm64e)")
                }
                guard let parsed = ArchSelection(rawValue: arguments[index]) else {
                    return .usageError("unknown architecture '\(arguments[index])' (expected arm64 or arm64e)")
                }
                arch = parsed
                index += 1
            case "--features":
                guard index < arguments.count else {
                    return .usageError("--features needs a value (arm64e)")
                }
                guard arguments[index] == "arm64e" else {
                    return .usageError("unknown feature set '\(arguments[index])' (expected arm64e)")
                }
                features = .arm64e
                index += 1
            case "--color":
                guard index < arguments.count else {
                    return .usageError("--color needs a value (auto, always, or never)")
                }
                guard let parsed = ColorMode(rawValue: arguments[index]) else {
                    return .usageError("unknown color mode '\(arguments[index])' (expected auto, always, or never)")
                }
                color = parsed
                index += 1
            case "--bytes":
                guard index < arguments.count else {
                    return .usageError("--bytes needs a hex byte string (e.g. \"1f 20 03 d5\")")
                }
                bytesArgument = arguments[index]
                index += 1
            default:
                if argument.hasPrefix("-") {
                    return .usageError("unknown option '\(argument)'")
                }
                if let existing = positional {
                    return .usageError("more than one input ('\(existing)' and '\(argument)')")
                }
                positional = argument
            }
        }

        let input: Invocation.Input
        switch (positional, bytesArgument) {
        case (.some, .some):
            return .usageError("--bytes and a positional input are mutually exclusive")
        case (nil, nil):
            return .usageError("no input (a file path, a 0x-prefixed word, or --bytes)")
        case let (nil, .some(hexBytes)):
            guard let bytes = parseByteString(hexBytes) else {
                return .usageError("--bytes wants pairs of hex digits separated by spaces or commas, got '\(hexBytes)'")
            }
            input = .bytes(bytes)
        case let (.some(argument), nil):
            if argument.hasPrefix("0x") || argument.hasPrefix("0X") {
                guard let word = parseWord(argument) else {
                    return .usageError("'\(argument)' is not a 32-bit instruction word (0x + 1...8 hex digits)")
                }
                input = .word(word)
            } else {
                input = .file(path: argument)
            }
        }

        if case .file = input, features != nil {
            return .usageError("--features applies to direct decode; use --arch to select a Mach-O slice")
        }
        if stats, semantics {
            return .usageError("--semantics has no effect on --stats output")
        }

        return .run(Invocation(
            input: input,
            arch: arch,
            features: features,
            json: json,
            semantics: semantics,
            stats: stats,
            color: color,
            quiet: quiet,
        ))
    }

    /// `0x`-prefixed 32-bit hex word.
    static func parseWord(_ argument: String) -> UInt32? {
        let digits = argument.dropFirst(2)
        guard !digits.isEmpty, digits.count <= 8 else { return nil }
        return UInt32(digits, radix: 16)
    }

    /// Hex byte string: pairs of hex digits, optionally separated by
    /// spaces and/or commas (`"1f 20 03 d5"`, `"1f,20,03,d5"`, `"1f2003d5"`).
    /// Digits map to values in one total pass, so no conversion can fail
    /// after validation.
    static func parseByteString(_ argument: String) -> [UInt8]? {
        var nibbles: [UInt8] = []
        nibbles.reserveCapacity(argument.utf8.count)
        for character in argument {
            let nibble: UInt8
            switch character {
            case " ", ",": continue
            case "0": nibble = 0
            case "1": nibble = 1
            case "2": nibble = 2
            case "3": nibble = 3
            case "4": nibble = 4
            case "5": nibble = 5
            case "6": nibble = 6
            case "7": nibble = 7
            case "8": nibble = 8
            case "9": nibble = 9
            case "a", "A": nibble = 10
            case "b", "B": nibble = 11
            case "c", "C": nibble = 12
            case "d", "D": nibble = 13
            case "e", "E": nibble = 14
            case "f", "F": nibble = 15
            default:
                return nil
            }
            nibbles.append(nibble)
        }
        guard !nibbles.isEmpty, nibbles.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(nibbles.count / 2)
        for i in stride(from: 0, to: nibbles.count, by: 2) {
            bytes.append(nibbles[i] << 4 | nibbles[i + 1])
        }
        return bytes
    }
}

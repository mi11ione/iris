// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The four things `iris` does, selected by the verb word (or inferred
/// from the input shape when the verb is omitted).
///
/// Each verb owns the set of flags it accepts, so a flag that does not
/// belong to a verb is one usage error from one code path rather than a
/// matrix of pairwise combination checks. `disasm`, `stats`, and
/// `functions` take a Mach-O file; `decode` takes raw words.
@frozen
public enum Verb: String, Sendable, Hashable, CaseIterable {
    /// Disassemble a Mach-O file's code sections (the default verb).
    case disasm
    /// Decode raw little-endian words (`0x<word>` or `--bytes`).
    case decode
    /// The instruction census of a Mach-O file.
    case stats
    /// The per-function output of a Mach-O file.
    case functions

    /// Whether this verb reads a Mach-O file (`disasm`/`stats`/`functions`)
    /// rather than raw words (`decode`).
    @inlinable
    public var readsFile: Bool {
        self != .decode
    }

    /// Whether `flag` (the long-option spelling, e.g. `--semantics`) is in
    /// this verb's accepted set. The globals `--help`/`-h`/`--version` are
    /// handled before per-verb parsing and are not listed here.
    ///
    /// - `disasm`: `--arch --semantics --json --color --quiet`
    /// - `decode`: `--features --semantics --json --color --bytes`
    /// - `stats`: `--arch --json --color --quiet`
    /// - `functions`: `--arch --json --color --quiet`
    ///
    /// `--bytes` is the decode input carrier (decode-only), so it is in
    /// decode's set and absent from the file verbs.
    @inlinable
    public func accepts(_ flag: String) -> Bool {
        switch flag {
        case "--json", "--color":
            true
        case "--quiet":
            self != .decode
        case "--semantics":
            self == .disasm || self == .decode
        case "--arch":
            readsFile
        case "--features", "--bytes":
            self == .decode
        default:
            false
        }
    }
}

/// One parsed `iris` invocation: the verb, the input, and the flags the
/// verb accepts.
@frozen
public struct Invocation: Sendable, Equatable {
    /// What to decode.
    @frozen
    public enum Input: Sendable, Equatable {
        /// A Mach-O file (thin or fat).
        case file(path: String)
        /// One little-endian instruction word (`iris 0xd503201f`).
        case word(UInt32)
        /// A byte sequence decoded as little-endian words (`--bytes`).
        case bytes([UInt8])

        /// Whether this is the Mach-O file input the file verbs carry.
        @inlinable
        public var isFile: Bool {
            if case .file = self { return true }
            return false
        }
    }

    /// The verb that selects the output mode.
    public var verb: Verb
    public var input: Input
    /// `--arch`: slice selection for the file verbs.
    public var arch: ArchSelection?
    /// `--features`: explicit decode features for `decode`.
    public var features: Features?
    /// `--json`: NDJSON output.
    public var json: Bool
    /// `--semantics`: per-line semantic annotations (`disasm` / `decode`).
    public var semantics: Bool
    /// `--color` policy.
    public var color: ColorMode
    /// `--quiet`: suppress diagnostics on stderr (the file verbs).
    public var quiet: Bool

    public init(
        verb: Verb,
        input: Input,
        arch: ArchSelection? = nil,
        features: Features? = nil,
        json: Bool = false,
        semantics: Bool = false,
        color: ColorMode = .auto,
        quiet: Bool = false,
    ) {
        self.verb = verb
        self.input = input
        self.arch = arch
        self.features = features
        self.json = json
        self.semantics = semantics
        self.color = color
        self.quiet = quiet
    }

    /// The features `decode` uses: explicit `--features` first, then plain
    /// ARM64 (the file verbs take their features from the selected slice,
    /// not this).
    @inlinable
    public var directDecodeFeatures: Features {
        features ?? []
    }
}

/// Result of parsing argv (everything after the executable name).
@frozen
public enum ParsedCommandLine: Sendable, Equatable {
    /// A well-formed invocation.
    case run(Invocation)
    /// `--help` / `-h`: the top-level help when `verb` is `nil`, that
    /// verb's help otherwise.
    case help(Verb?)
    /// `--version`.
    case version
    /// A usage error with its message (exit code 1).
    case usageError(String)
}

public extension ParsedCommandLine {
    /// Parse argv. The grammar is `iris [verb] [flags] [input]`: a leading
    /// verb word (`disasm`/`decode`/`stats`/`functions`) is consumed if
    /// present, otherwise the verb is inferred from the input shape (a
    /// `0x`-prefixed token or `--bytes` is `decode`, a path is `disasm`).
    /// Flags may appear in any order around the single positional input
    /// and value flags repeat last-wins. The globals `--help`/`-h` and
    /// `--version` win wherever they appear.
    static func parse(_ arguments: [String]) -> ParsedCommandLine {
        // Bare `iris` prints the top-level help.
        if arguments.isEmpty {
            return .help(nil)
        }
        // The globals win regardless of position. --version short circuits
        // unconditionally; --help renders the named verb's help, so the
        // verb is resolved before deciding which help to show.
        if arguments.contains("--version") {
            return .version
        }

        // Resolve the verb: the first bare (non-flag) token, if it is a
        // verb word, is the verb and is dropped from the input stream;
        // value-flag values are stepped over so a leading flag does not
        // hide the verb behind it ('iris --color never functions X').
        // Any other first bare token is the input, and the verb is then
        // inferred from its shape.
        let explicitVerb: Verb?
        var rest = arguments
        if let position = firstBareTokenIndex(arguments), let known = Verb(rawValue: arguments[position]) {
            explicitVerb = known
            rest.remove(at: position)
        } else {
            explicitVerb = nil
        }

        if arguments.contains("--help") || arguments.contains("-h") {
            return .help(explicitVerb)
        }

        let resolvedVerb = explicitVerb ?? inferVerb(rest)
        return parseFor(resolvedVerb, rest, verbWasExplicit: explicitVerb != nil)
    }

    /// Index of the first bare (non-`-`) token, stepping over the value of
    /// each value-flag so a flag's argument is never mistaken for it.
    /// `nil` when argv is all flags (or empty).
    static func firstBareTokenIndex(_ arguments: [String]) -> Int? {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if isValueFlag(argument) {
                index += 2
                continue
            }
            if argument.hasPrefix("-") {
                index += 1
                continue
            }
            return index
        }
        return nil
    }

    /// Infer the verb from argv with no verb word: `--bytes` anywhere, or a
    /// leading-`0x` positional, means `decode`; otherwise `disasm`. Empty
    /// argv resolves to `disasm` (its "no input" error is the one a bare
    /// path would hit, and bare `iris` is intercepted as help before this).
    static func inferVerb(_ arguments: [String]) -> Verb {
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            if argument == "--bytes" {
                return .decode
            }
            if isValueFlag(argument) {
                index += 2
                continue
            }
            if argument.hasPrefix("-") {
                index += 1
                continue
            }
            return (argument.hasPrefix("0x") || argument.hasPrefix("0X")) ? .decode : .disasm
        }
        return .disasm
    }

    /// Whether `argument` is a flag that consumes the following token as
    /// its value (used to step over values during verb inference).
    static func isValueFlag(_ argument: String) -> Bool {
        argument == "--arch" || argument == "--features"
            || argument == "--color" || argument == "--bytes"
    }

    /// Parse `arguments` (the tokens after any verb word) against `verb`'s
    /// accepted flag set. `verbWasExplicit` scopes the verb in error
    /// messages: an explicit `iris stats …` reports `iris stats: error: …`,
    /// an inferred one reports `iris: error: …`.
    static func parseFor(_ verb: Verb, _ arguments: [String], verbWasExplicit: Bool) -> ParsedCommandLine {
        let label = verbWasExplicit ? "iris \(verb.rawValue): error:" : "iris: error:"

        var positional: String?
        var bytesArgument: String?
        var arch: ArchSelection?
        var features: Features?
        var json = false
        var semantics = false
        var color: ColorMode = .auto
        var quiet = false

        // A flag this verb does not accept falls through every `where`
        // clause to the `default` unknown-option arm, the single rule that
        // replaces every old pairwise flag-combination check.
        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            index += 1
            switch argument {
            case "--json" where verb.accepts("--json"):
                json = true
            case "--semantics" where verb.accepts("--semantics"):
                semantics = true
            case "--quiet" where verb.accepts("--quiet"):
                quiet = true
            case "--arch" where verb.accepts("--arch"):
                guard index < arguments.count else {
                    return .usageError("\(label) --arch needs a value (arm64 or arm64e)")
                }
                guard let parsed = ArchSelection(rawValue: arguments[index]) else {
                    return .usageError("\(label) unknown architecture '\(arguments[index])' (expected arm64 or arm64e)")
                }
                arch = parsed
                index += 1
            case "--features" where verb.accepts("--features"):
                guard index < arguments.count else {
                    return .usageError("\(label) --features needs a value (arm64e)")
                }
                guard arguments[index] == "arm64e" else {
                    return .usageError("\(label) unknown feature set '\(arguments[index])' (expected arm64e)")
                }
                features = .arm64e
                index += 1
            case "--color" where verb.accepts("--color"):
                guard index < arguments.count else {
                    return .usageError("\(label) --color needs a value (auto, always, or never)")
                }
                guard let parsed = ColorMode(rawValue: arguments[index]) else {
                    return .usageError("\(label) unknown color mode '\(arguments[index])' (expected auto, always, or never)")
                }
                color = parsed
                index += 1
            case "--bytes" where verb.accepts("--bytes"):
                guard index < arguments.count else {
                    return .usageError("\(label) --bytes needs a hex byte string (e.g. \"1f 20 03 d5\")")
                }
                bytesArgument = arguments[index]
                index += 1
            case "--bytes" where verb.readsFile:
                // A file verb reads a Mach-O; --bytes carries raw words, the
                // same confusion as a leading 0x positional below, so it
                // redirects to decode rather than dead-ending at "unknown
                // option".
                return .usageError("\(label) --bytes carries raw words; use 'iris decode --bytes …'")
            default:
                if argument.hasPrefix("-") {
                    return .usageError("\(label) unknown option '\(argument)'")
                }
                if let existing = positional {
                    return .usageError("\(label) more than one input ('\(existing)' and '\(argument)')")
                }
                positional = argument
            }
        }

        return resolveInput(
            verb: verb, label: label, positional: positional, bytesArgument: bytesArgument,
            arch: arch, features: features, json: json, semantics: semantics, color: color, quiet: quiet,
        )
    }

    /// Turn the parsed positional / `--bytes` into the verb's input,
    /// rejecting an input shape the verb cannot take (a `decode` word for a
    /// file verb, a file path for `decode`).
    private static func resolveInput(
        verb: Verb,
        label: String,
        positional: String?,
        bytesArgument: String?,
        arch: ArchSelection?,
        features: Features?,
        json: Bool,
        semantics: Bool,
        color: ColorMode,
        quiet: Bool,
    ) -> ParsedCommandLine {
        let input: Invocation.Input
        switch (positional, bytesArgument) {
        case (.some, .some):
            return .usageError("\(label) --bytes and a positional input are mutually exclusive")
        case (nil, nil):
            return .usageError(verb.readsFile
                ? "\(label) no input (a Mach-O file path)"
                : "\(label) no input (a 0x-prefixed word, or --bytes)")
        case let (nil, .some(hexBytes)):
            // --bytes is decode-only (the file verbs do not accept it), so
            // reaching here means verb == .decode.
            guard let bytes = parseByteString(hexBytes) else {
                return .usageError("\(label) --bytes wants pairs of hex digits separated by spaces or commas, got '\(hexBytes)'")
            }
            input = .bytes(bytes)
        case let (.some(argument), nil):
            let looksLikeWord = argument.hasPrefix("0x") || argument.hasPrefix("0X")
            if verb.readsFile {
                // A file verb takes a path. A 0x token here is a decode
                // input the user routed to the wrong verb.
                if looksLikeWord {
                    return .usageError("\(label) '\(argument)' is a raw word; use 'iris decode \(argument)'")
                }
                input = .file(path: argument)
            } else {
                // decode takes a word; a non-0x positional is not one.
                guard looksLikeWord else {
                    return .usageError("\(label) '\(argument)' is not a 0x-prefixed word; use 'iris disasm \(argument)' for a file")
                }
                guard let word = parseWord(argument) else {
                    return .usageError("\(label) '\(argument)' is not a 32-bit instruction word (0x + 1...8 hex digits)")
                }
                input = .word(word)
            }
        }

        return .run(Invocation(
            verb: verb,
            input: input,
            arch: arch,
            features: features,
            json: json,
            semantics: semantics,
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

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The four things `iris` does, selected by the verb word or inferred from the
/// input shape.
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

    /// Whether `flag` is in this verb's accepted set.
    @inlinable
    public func accepts(_ flag: String) -> Bool {
        switch flag {
        case "--json", "--color":
            true
        case "--slim":
            true
        case "--quiet":
            self != .decode
        case "--semantics":
            self == .disasm || self == .decode
        case "--arch":
            readsFile
        case "--features", "--bytes", "--at":
            self == .decode
        case "--function", "--range":
            self == .disasm
        default:
            false
        }
    }
}

/// One parsed `iris` invocation.
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

    /// A `--range start:end` half-open VM-address window.
    @frozen
    public struct AddressRange: Sendable, Equatable {
        /// Inclusive low bound.
        public var start: UInt64
        /// Exclusive high bound.
        public var end: UInt64

        @inlinable
        public init(start: UInt64, end: UInt64) {
            self.start = start
            self.end = end
        }
    }

    /// The verb that selects the output mode.
    public var verb: Verb
    public var input: Input
    /// `--arch`: slice selection for the file verbs.
    public var arch: ArchSelection?
    /// `--features`: explicit decode features for `decode`.
    public var features: Features?
    /// `--at`: the VM base address the raw words are decoded at, so relative
    /// branches and PC-relative addressing resolve against the window's real
    /// place in memory.
    public var address: UInt64
    /// `--json`: NDJSON output.
    public var json: Bool
    /// `--slim`: the compact `--json` projection (drops zero-signal constants
    /// and empty/false fields). Only meaningful with `--json`.
    public var slim: Bool
    /// `--semantics`: per-line semantic annotations (`disasm` / `decode`).
    public var semantics: Bool
    /// `--color` policy.
    public var color: ColorMode
    /// `--quiet`: suppress diagnostics on stderr (the file verbs).
    public var quiet: Bool
    /// `--function <name>`: limit `disasm` to one function's instructions.
    public var function: String?
    /// `--range <start>:<end>`: limit `disasm` to a half-open VM window.
    public var range: AddressRange?

    public init(
        verb: Verb,
        input: Input,
        arch: ArchSelection? = nil,
        features: Features? = nil,
        address: UInt64 = 0,
        json: Bool = false,
        slim: Bool = false,
        semantics: Bool = false,
        color: ColorMode = .auto,
        quiet: Bool = false,
        function: String? = nil,
        range: AddressRange? = nil,
    ) {
        self.verb = verb
        self.input = input
        self.arch = arch
        self.features = features
        self.address = address
        self.json = json
        self.slim = slim
        self.semantics = semantics
        self.color = color
        self.quiet = quiet
        self.function = function
        self.range = range
    }

    /// The features `decode` uses.
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
    /// `--help` / `-h`.
    case help(Verb?)
    /// `--version`.
    case version
    /// A usage error with its message (exit code 1).
    case usageError(String)
}

public extension ParsedCommandLine {
    /// Parse argv. The grammar is `iris [verb] [flags] [input]`: a leading
    /// verb word is consumed if present, otherwise inferred from the input
    /// shape (a `0x` token or `--bytes` is `decode`, a path is `disasm`).
    /// Flags may appear in any order and value flags are last-wins;
    /// `--help`/`-h` and `--version` win wherever they appear.
    static func parse(_ arguments: [String]) -> ParsedCommandLine {
        if arguments.isEmpty {
            return .help(nil)
        }
        if arguments.contains("--version") {
            return .version
        }

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

    /// Infer the verb from argv with no verb word.
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

    /// Whether `argument` is a flag that consumes the following token as its
    /// value (used to step over values during verb inference).
    static func isValueFlag(_ argument: String) -> Bool {
        argument == "--arch" || argument == "--features"
            || argument == "--color" || argument == "--bytes"
            || argument == "--function" || argument == "--range"
            || argument == "--at"
    }

    /// Parse `arguments` (the tokens after any verb word) against `verb`'s
    /// accepted flag set.
    static func parseFor(_ verb: Verb, _ arguments: [String], verbWasExplicit: Bool) -> ParsedCommandLine {
        let label = verbWasExplicit ? "iris \(verb.rawValue): error:" : "iris: error:"

        var positional: String?
        var bytesArgument: String?
        var arch: ArchSelection?
        var features: Features?
        var addressArgument: String?
        var json = false
        var slim = false
        var semantics = false
        var color: ColorMode = .auto
        var quiet = false
        var function: String?
        var rangeArgument: String?

        var index = 0
        while index < arguments.count {
            let argument = arguments[index]
            index += 1
            switch argument {
            case "--json" where verb.accepts("--json"):
                json = true
            case "--slim" where verb.accepts("--slim"):
                slim = true
            case "--semantics" where verb.accepts("--semantics"):
                semantics = true
            case "--quiet" where verb.accepts("--quiet"):
                quiet = true
            case "--function" where verb.accepts("--function"):
                guard index < arguments.count else {
                    return .usageError("\(label) --function needs a function name")
                }
                function = arguments[index]
                index += 1
            case "--range" where verb.accepts("--range"):
                guard index < arguments.count else {
                    return .usageError("\(label) --range needs a value (start:end, e.g. 0x1080:0x1170)")
                }
                rangeArgument = arguments[index]
                index += 1
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
            case "--at" where verb.accepts("--at"):
                guard index < arguments.count else {
                    return .usageError("\(label) --at needs a value (a base address, 0x-hex or decimal, e.g. 0xfffffe0007b3c000)")
                }
                addressArgument = arguments[index]
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
                return .usageError("\(label) --bytes carries raw words; use 'iris decode --bytes …'")
            case "--at" where verb.readsFile:
                return .usageError("\(label) --at bases raw words; a Mach-O file carries its own addresses")
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
            arch: arch, features: features, addressArgument: addressArgument,
            json: json, slim: slim, semantics: semantics,
            color: color, quiet: quiet, function: function, rangeArgument: rangeArgument,
        )
    }

    /// Turn the parsed positional / `--bytes` into the verb's input, rejecting
    /// an input shape the verb cannot take (a `decode` word for a file verb, a
    /// file path for `decode`).
    private static func resolveInput(
        verb: Verb,
        label: String,
        positional: String?,
        bytesArgument: String?,
        arch: ArchSelection?,
        features: Features?,
        addressArgument: String?,
        json: Bool,
        slim: Bool,
        semantics: Bool,
        color: ColorMode,
        quiet: Bool,
        function: String?,
        rangeArgument: String?,
    ) -> ParsedCommandLine {
        if slim, !json {
            return .usageError("\(label) --slim shapes --json output; add --json (or drop --slim)")
        }
        if function != nil, rangeArgument != nil {
            return .usageError("\(label) --function and --range both scope the output; use one")
        }
        var address: UInt64 = 0
        if let addressArgument {
            guard let parsed = parseAddress(addressArgument) else {
                return .usageError("\(label) --at wants a base address as 0x-hex or decimal, got '\(addressArgument)'")
            }
            address = parsed
        }
        var range: Invocation.AddressRange?
        if let rangeArgument {
            guard let parsed = parseAddressRange(rangeArgument) else {
                return .usageError("\(label) --range wants start:end as 0x-hex or decimal with start < end, got '\(rangeArgument)'")
            }
            range = parsed
        }
        let input: Invocation.Input
        switch (positional, bytesArgument) {
        case (.some, .some):
            return .usageError("\(label) --bytes and a positional input are mutually exclusive")
        case (nil, nil):
            return .usageError(verb.readsFile
                ? "\(label) no input (a Mach-O file path)"
                : "\(label) no input (a 0x-prefixed word, or --bytes)")
        case let (nil, .some(hexBytes)):
            guard let bytes = parseByteString(hexBytes) else {
                return .usageError("\(label) --bytes wants pairs of hex digits separated by spaces or commas, got '\(hexBytes)'")
            }
            input = .bytes(bytes)
        case let (.some(argument), nil):
            let looksLikeWord = argument.hasPrefix("0x") || argument.hasPrefix("0X")
            if verb.readsFile {
                if looksLikeWord {
                    return .usageError("\(label) '\(argument)' is a raw word; use 'iris decode \(argument)'")
                }
                input = .file(path: argument)
            } else {
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
            address: address,
            json: json,
            slim: slim,
            semantics: semantics,
            color: color,
            quiet: quiet,
            function: function,
            range: range,
        ))
    }

    /// Parse a `--range` value `start:end` into a half-open
    /// ``Invocation/AddressRange``.
    static func parseAddressRange(_ argument: String) -> Invocation.AddressRange? {
        let parts = argument.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }
        guard let start = parseAddress(parts[0]), let end = parseAddress(parts[1]), start < end else { return nil }
        return Invocation.AddressRange(start: start, end: end)
    }

    /// A single `--range` bound.
    static func parseAddress(_ token: some StringProtocol) -> UInt64? {
        if token.hasPrefix("0x") || token.hasPrefix("0X") {
            let digits = token.dropFirst(2)
            return digits.isEmpty ? nil : UInt64(digits, radix: 16)
        }
        return UInt64(token)
    }

    /// `0x`-prefixed 32-bit hex word.
    static func parseWord(_ argument: String) -> UInt32? {
        let digits = argument.dropFirst(2)
        guard !digits.isEmpty, digits.count <= 8 else { return nil }
        return UInt32(digits, radix: 16)
    }

    /// Hex byte string.
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

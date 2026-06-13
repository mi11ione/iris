// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Iris

/// The `iris` tool: argv in, lines out, exit code back.
///
/// Exit codes: 0 success; 1 usage error; 2 unreadable or not Mach-O;
/// 3 no decodable code sections / requested architecture unavailable.
/// Listings and NDJSON go to `writeOutput` (stdout); diagnostics and
/// errors to `writeError` (stderr). `--quiet` suppresses walker
/// diagnostics, never error messages.
public enum CLI {
    /// The tool's release version, matching the package tag.
    public static let version = "0.3.0"

    /// Exit code for success.
    public static let exitSuccess: Int32 = 0
    /// Exit code for a usage error.
    public static let exitUsage: Int32 = 1
    /// Exit code for an unreadable or non-Mach-O input.
    public static let exitNotMachO: Int32 = 2
    /// Exit code for "nothing to decode": no code sections, or the
    /// requested architecture is not in the file.
    public static let exitNoCode: Int32 = 3

    /// Run one invocation. Output is emitted incrementally through the
    /// sinks (NDJSON and listings stream line by line; nothing
    /// accumulates whole-file).
    public static func run(
        arguments: [String],
        standardOutputIsTTY: Bool,
        writeOutput: (String) -> Void,
        writeError: (String) -> Void,
    ) -> Int32 {
        switch ParsedCommandLine.parse(arguments) {
        case let .help(verb):
            writeOutput(helpText(for: verb))
            return exitSuccess
        case .version:
            writeOutput("iris \(version)\n")
            return exitSuccess
        case let .usageError(message):
            // The parser bakes the full `iris[ verb]: error:` scope into
            // the message, so it prints verbatim.
            writeError(message + "\n")
            writeError("run 'iris --help' for usage\n")
            return exitUsage
        case let .run(invocation):
            return run(invocation, standardOutputIsTTY: standardOutputIsTTY, writeOutput: writeOutput, writeError: writeError)
        }
    }

    /// Dispatch a parsed invocation to the file or direct-decode path.
    static func run(
        _ invocation: Invocation,
        standardOutputIsTTY: Bool,
        writeOutput: (String) -> Void,
        writeError: (String) -> Void,
    ) -> Int32 {
        let palette = Palette(enabled: invocation.color.resolved(standardOutputIsTTY: standardOutputIsTTY))
        switch invocation.input {
        case let .file(path):
            return runFile(
                path: path,
                invocation: invocation,
                palette: palette,
                writeOutput: writeOutput,
                writeError: writeError,
            )
        case let .word(word):
            var bytes: [UInt8] = []
            bytes.reserveCapacity(4)
            bytes.append(UInt8(word & 0xFF))
            bytes.append(UInt8((word >> 8) & 0xFF))
            bytes.append(UInt8((word >> 16) & 0xFF))
            bytes.append(UInt8((word >> 24) & 0xFF))
            return runDirect(bytes: bytes, invocation: invocation, palette: palette, writeOutput: writeOutput)
        case let .bytes(bytes):
            return runDirect(bytes: bytes, invocation: invocation, palette: palette, writeOutput: writeOutput)
        }
    }

    /// The `decode` verb: a stream over the given bytes at address 0,
    /// honoring `--features`. Such a stream provably emits no diagnostics
    /// (no spans, no address wrap from base 0), so only the records need
    /// rendering. `--json` emits the per-instruction objects; otherwise a
    /// listing, with `--semantics` annotating each decoded line.
    static func runDirect(
        bytes: [UInt8],
        invocation: Invocation,
        palette: Palette,
        writeOutput: (String) -> Void,
    ) -> Int32 {
        let stream = InstructionStream(bytes: bytes, features: invocation.directDecodeFeatures)
        if invocation.json {
            for instruction in stream {
                writeOutput(JSONText.instructionLine(instruction) + "\n")
            }
            return exitSuccess
        }
        let renderer = ListingRenderer(palette: palette, includeSemantics: invocation.semantics)
        renderer.emitStream(stream, emit: writeOutput)
        return exitSuccess
    }

    /// The Mach-O file mode: walk, report, render.
    static func runFile(
        path: String,
        invocation: Invocation,
        palette: Palette,
        writeOutput: (String) -> Void,
        writeError: (String) -> Void,
    ) -> Int32 {
        switch MachOWalker.walk(path: path, arch: invocation.arch) {
        case let .unreadable(detail):
            writeError("iris: error: \(detail)\n")
            return exitNotMachO
        case let .notMachO(detail):
            writeError("iris: error: \(detail)\n")
            return exitNotMachO
        case let .archUnavailable(requested, available):
            let want = requested.map { "no \($0.rawValue) slice" } ?? "no arm64 or arm64e slice"
            writeError("iris: error: \(want) in '\(path)' (available: \(available.joined(separator: ", ")))\n")
            return exitNoCode
        case let .binary(binary):
            if !invocation.quiet {
                for diagnostic in binary.diagnostics {
                    writeError("iris: \(diagnostic.description)\n")
                }
            }
            guard !binary.codeSections.isEmpty else {
                writeError("iris: error: no decodable code sections in '\(path)' (\(binary.architecture))\n")
                return exitNoCode
            }
            func surface(_ section: CodeSection, _ diagnostic: Diagnostic) {
                guard !invocation.quiet, let warning = streamWarning(section: section, diagnostic: diagnostic) else { return }
                writeError(warning)
            }
            // The file verb selects the output mode. `decode` never reaches
            // here (the parser pairs it with word/byte input, the file
            // verbs with a path), so it falls in with the listing path for
            // totality rather than a trap.
            switch invocation.verb {
            case .stats:
                var census = Census()
                for section in binary.codeSections {
                    let stream = section.instructions(features: binary.features)
                    for diagnostic in stream.diagnostics {
                        surface(section, diagnostic)
                    }
                    census.add(stream)
                }
                emit(census: census, json: invocation.json, writeOutput: writeOutput)
            case .functions:
                // Diagnostics route through `surface` exactly as the
                // per-instruction paths do.
                let carved = FunctionCarver.functions(of: binary, onStreamDiagnostic: surface)
                if invocation.json {
                    let jsonContext = JSONText.SymbolContext(binary: binary)
                    for function in carved {
                        writeOutput(JSONText.functionLine(function, context: jsonContext) + "\n")
                    }
                } else {
                    FunctionSummary.emit(functions: carved, binary: binary, palette: palette, emit: writeOutput)
                }
            case .disasm, .decode:
                if invocation.json {
                    let jsonContext = JSONText.SymbolContext(binary: binary)
                    for section in binary.codeSections {
                        let stream = section.instructions(features: binary.features)
                        for diagnostic in stream.diagnostics {
                            surface(section, diagnostic)
                        }
                        for instruction in stream {
                            writeOutput(JSONText.instructionLine(instruction, context: jsonContext) + "\n")
                        }
                    }
                } else {
                    let renderer = ListingRenderer(palette: palette, includeSemantics: invocation.semantics)
                    renderer.emitListing(for: binary, emit: writeOutput, onStreamDiagnostic: surface)
                }
            }
            return exitSuccess
        }
    }

    /// The stderr line for one stream-level decode diagnostic, or `nil`
    /// for the kinds the listing already carries inline
    /// (data-in-code span echoes are provenance: every covered word is
    /// rendered as data with its kind, and `--json` carries `isData`).
    static func streamWarning(section: CodeSection, diagnostic: Diagnostic) -> String? {
        switch diagnostic.kind {
        case .dataInCodeSpanEncountered:
            nil
        case let .addressSpaceWrapped(offset):
            "iris: warning: \(section.displayName): addresses wrap past 2^64 at buffer offset \(offset)\n"
        }
    }

    /// Census output: one JSON object or the table.
    static func emit(census: Census, json: Bool, writeOutput: (String) -> Void) {
        if json {
            writeOutput(census.jsonObject() + "\n")
        } else {
            for line in census.tableLines() {
                writeOutput(line + "\n")
            }
        }
    }

    /// The help to print: the top-level overview when `verb` is `nil`,
    /// otherwise that verb's usage and flag set.
    public static func helpText(for verb: Verb?) -> String {
        switch verb {
        case nil: helpText
        case .disasm: disasmHelpText
        case .decode: decodeHelpText
        case .stats: statsHelpText
        case .functions: functionsHelpText
        }
    }

    /// Top-level `iris --help` (and bare `iris`): the verb list and the
    /// global options.
    public static let helpText = """
    iris is an ARM64/ARM64E disassembler.

    usage:
      iris <file>                disassemble a Mach-O binary's code sections
      iris 0x<word>              decode one 32-bit instruction word
      iris <verb> [options] ...  run a verb explicitly

    verbs:
      disasm <file>              disassemble a Mach-O binary (the default verb,
                                 so 'iris <file>' is the same)
      decode <0x<word>|--bytes>  decode raw little-endian words (inferred for
                                 'iris 0x<word>' and 'iris --bytes ...')
      stats <file>               the instruction census of a Mach-O binary
      functions <file>           the per-function output of a Mach-O binary

    Omit the verb and iris picks it from the input: a 0x-prefixed word or
    --bytes is decode, a path is disasm. To disassemble a file whose name is
    a verb word, write the path ('./stats') or use 'iris disasm stats'.

    global options:
      --version                  print the version
      --help, -h                 print this help, or a verb's help after the
                                 verb ('iris stats --help')

    Run 'iris <verb> --help' for a verb's own options.

    exit codes:
      0  success
      1  usage error
      2  unreadable input, or not a Mach-O / fat binary
      3  no decodable code sections, or the architecture is unavailable

    """

    /// `iris disasm --help`.
    public static let disasmHelpText = """
    iris disasm: disassemble a Mach-O binary's code sections.

    usage:
      iris disasm [options] <file>
      iris [options] <file>            (disasm is the default verb)

    The listing carries symbols and function starts from the binary, branch
    targets resolved and symbolicated, and data-in-code rendered as data.

    options:
      --arch <arm64|arm64e>        select the slice of a fat binary
                                   (default: arm64e first, then arm64)
      --semantics                  append per-line semantic annotations
                                   (reads/writes/flags/memory/ordering/branch)
      --json                       emit NDJSON, one object per instruction
                                   (schema: the "JSON output" DocC article,
                                   which already carries the semantics)
      --color <auto|always|never>  ANSI color (default: auto, a TTY only)
      --quiet                      suppress decode diagnostics on stderr
                                   (malformed-input warnings). Fatal errors
                                   such as a missing file are still reported.
      --help, -h                   print this help

    """

    /// `iris decode --help`.
    public static let decodeHelpText = """
    iris decode: decode raw little-endian instruction words.

    usage:
      iris decode [options] 0x<word>
      iris decode [options] --bytes "<hex>"
      iris 0x<word>                    (decode is inferred from the input)

    word vs bytes order: 0x<word> is the instruction word as written
    (0xd503201f), so its bytes read high to low. --bytes is memory order
    (little-endian), so "1f 20 03 d5" is the same instruction.

    options:
      --features <arm64e>          decode with the ARM64E extensions
                                   (LDRAA/LDRAB and the rest)
      --semantics                  append per-line semantic annotations
                                   (reads/writes/flags/memory/ordering/branch)
      --json                       emit NDJSON, one object per instruction
      --color <auto|always|never>  ANSI color (default: auto, a TTY only)
      --help, -h                   print this help

    """

    /// `iris stats --help`.
    public static let statsHelpText = """
    iris stats: the instruction census of a Mach-O binary.

    Censuses the binary for pointer authentication, MTE, AMX, and crypto
    sites, plus per-mnemonic and per-category counts and word totals.

    usage:
      iris stats [options] <file>

    options:
      --arch <arm64|arm64e>        select the slice of a fat binary
                                   (default: arm64e first, then arm64)
      --json                       emit one census object instead of the table
      --color <auto|always|never>  ANSI color (default: auto, a TTY only)
      --quiet                      suppress decode diagnostics on stderr
      --help, -h                   print this help

    """

    /// `iris functions --help`.
    public static let functionsHelpText = """
    iris functions: the per-function output of a Mach-O binary.

    One row per function (address, name, instruction count, calls, PAC use),
    or with --json one "kind":"function" object per function wrapping its
    instructions. Boundaries come from LC_FUNCTION_STARTS and section
    membership (loader data, no control-flow inference).

    usage:
      iris functions [options] <file>

    options:
      --arch <arm64|arm64e>        select the slice of a fat binary
                                   (default: arm64e first, then arm64)
      --json                       emit one "kind":"function" object per
                                   function instead of the summary table
      --color <auto|always|never>  ANSI color (default: auto, a TTY only)
      --quiet                      suppress decode diagnostics on stderr
      --help, -h                   print this help

    """
}

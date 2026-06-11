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
    public static let version = "0.1.0"

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
        case .help:
            writeOutput(helpText)
            return exitSuccess
        case .version:
            writeOutput("iris \(version)\n")
            return exitSuccess
        case let .usageError(message):
            writeError("iris: error: \(message)\n")
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

    /// The direct-decode modes: a stream over the given bytes at
    /// address 0, honoring `--features` / the `--arch` alias. Such a
    /// stream provably emits no diagnostics (no spans, no address wrap
    /// from base 0), so only the records need rendering.
    static func runDirect(
        bytes: [UInt8],
        invocation: Invocation,
        palette: Palette,
        writeOutput: (String) -> Void,
    ) -> Int32 {
        let stream = InstructionStream(bytes: bytes, features: invocation.directDecodeFeatures)
        if invocation.stats {
            var census = Census()
            census.add(stream)
            emit(census: census, json: invocation.json, writeOutput: writeOutput)
            return exitSuccess
        }
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
            if invocation.stats {
                var census = Census()
                for section in binary.codeSections {
                    let stream = section.instructions(features: binary.features)
                    for diagnostic in stream.diagnostics {
                        surface(section, diagnostic)
                    }
                    census.add(stream)
                }
                emit(census: census, json: invocation.json, writeOutput: writeOutput)
                return exitSuccess
            }
            if invocation.json {
                for section in binary.codeSections {
                    let stream = section.instructions(features: binary.features)
                    for diagnostic in stream.diagnostics {
                        surface(section, diagnostic)
                    }
                    for instruction in stream {
                        writeOutput(JSONText.instructionLine(instruction) + "\n")
                    }
                }
                return exitSuccess
            }
            let renderer = ListingRenderer(palette: palette, includeSemantics: invocation.semantics)
            renderer.emitListing(for: binary, emit: writeOutput, onStreamDiagnostic: surface)
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

    /// `--help`, printed to stdout.
    public static let helpText = """
    iris — ARM64/ARM64E disassembler

    usage:
      iris [options] <file>           disassemble a Mach-O binary's code sections
      iris [options] 0x<word>         decode one little-endian instruction word
      iris [options] --bytes "<hex>"  decode hex bytes as little-endian words

    options:
      --arch <arm64|arm64e>        select the slice of a fat binary
                                   (default: arm64e first, then arm64);
                                   in direct decode, an alias for --features
      --features <arm64e>          direct decode with ARM64E extensions
      --semantics                  append per-line semantic annotations
                                   (reads/writes/flags/memory/ordering/branch)
      --json                       emit NDJSON, one object per instruction
                                   (schema: the "JSON output" DocC article;
                                   includes semantics, so --semantics adds
                                   nothing)
      --stats                      emit an instruction census instead of a
                                   listing (with --json: one census object)
      --color <auto|always|never>  ANSI color (default: auto — only on a TTY)
      --quiet                      suppress diagnostics on stderr
      --version                    print the version
      --help, -h                   print this help

    exit codes:
      0  success
      1  usage error
      2  unreadable input, or not a Mach-O / fat binary
      3  no decodable code sections, or the architecture is unavailable

    """
}

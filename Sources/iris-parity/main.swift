// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// iris-parity — the in-repo trust instrument. Not a
// shipped product: it re-earns the library's correctness claims against
// external ground truth (llvm-mc) and the library's own totality and
// determinism contracts, on every PR and every night.
//
//   tsv         diff Iris against committed/external TSV corpora
//   live        seeded random sweep vs live llvm-mc at maximal mattr
//   exhaustive  full 2^32 totality + two-pass determinism digest
//   semantic    per-family expected-attribute checker sweep

import Foundation

/// The tool's release version, matching the package tag.
let parityVersion = "0.2.0"

let usage = """
usage: iris-parity <subcommand> [options]

subcommands:
  tsv <path | --family <f|all>> [--reanchor] [--llvm-mc <path>] [--limit N]
      Diff decode+text against TSV rows (`hex<TAB>expected_text`; real-corpus
      layout auto-detected). Resolves in-repo Tests/Fixtures/Decode fixtures
      by family, or an external corpus tree via IRIS_DECODE_CORPUS
      (decode-<family>/{synthetic.tsv,real_text.tsv}). Empty expected cell
      means the word must decode UNDEFINED. --reanchor re-drives divergent
      rows through llvm-mc at the family's maximal mattr and reports
      harvest-era oracle-blind cells separately, never as Iris failures.
      Exits non-zero on any true divergence.

  live --family <f|all> [--count N] [--seed S] [--llvm-mc <path>] [--chunk N]
      Seeded random sweep per encoding partition, diffed against live
      llvm-mc at the family's maximal mattr. Default 65,536 words/family.

  exhaustive [--partition <op0>|all] [--jobs N]
      Decode the full 2^32 word space (default) or one op0 partition,
      asserting totality (well-formed record per word, no crash) and
      determinism (two independent passes, identical digests). Use a
      release build: `swift run -c release iris-parity exhaustive all`.

  semantic --family <f|all> [--count N] [--seed S]
      Run the @_spi(Validation) semantic checkers over the family's
      synthetic corpus rows plus a seeded random partition sweep.

families: dpi, bes, ls, dpr, simd-fp, crypto-apple, reserved
numeric options: counts/jobs/limit/chunk take non-negative decimal;
  --seed takes decimal or 0x-prefixed hex; a value that fails to parse
  is a loud usage error (exit 1), never a silent default
environment: IRIS_LLVM_MC (oracle path), IRIS_DECODE_CORPUS (corpus tree)
exit codes: 0 clean, 1 divergence/issue/malformed option value, 2 setup error

Known deviations (KNOWN-DEVIATIONS.md) classify expected
divergences: matching rows are reported under their catalogue id and do
not gate.
"""

@available(macOS 10.15, *)
func dispatchSubcommand(_ subcommand: String, _ rest: [String]) async -> Int32 {
    switch subcommand {
    case "tsv":
        return await runTSVCommand(rest)
    case "live":
        return runLiveCommand(rest)
    case "exhaustive":
        return await runExhaustiveCommand(rest)
    case "semantic":
        return runSemanticCommand(rest)
    case "--help", "-h", "help":
        print(usage)
        return 0
    case "--version", "version":
        print("iris-parity \(parityVersion)")
        return 0
    default:
        eprint("iris-parity: unknown subcommand `\(subcommand)`")
        print(usage)
        return 2
    }
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let subcommand = arguments.first else {
    print(usage)
    exit(2)
}

let rest = Array(arguments.dropFirst())

// The library floors at the SwiftPM tools-6.0 defaults (no `platforms:`
// stanza — a deliberate library decision this tool must not disturb), so Swift
// concurrency carries an availability condition here. The detached task
// runs on the cooperative pool; the main thread blocks on the semaphore
// outside it.
if #available(macOS 10.15, *) {
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var exitCode: Int32 = 2
    Task.detached {
        exitCode = await dispatchSubcommand(subcommand, rest)
        semaphore.signal()
    }
    semaphore.wait()
    exit(exitCode)
} else {
    eprint("iris-parity: needs macOS 10.15+ (the library itself floors lower)")
    exit(2)
}

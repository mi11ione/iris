// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation

/// Resolve the synthetic golden-corpus TSV for one decode family.
///
/// Default: the tracked in-repo fixture
/// `Tests/Fixtures/Decode/synthetic-<family>.tsv`, resolved relative to
/// this source file so `swift test` finds it regardless of the working
/// directory. When the `IRIS_DECODE_CORPUS` environment variable is set,
/// it must point at the root of an externally maintained corpus tree
/// laid out as `decode-<family>/synthetic.tsv` (the layout of the parent
/// project's `Corpus/` directory); the golden suites then run the same
/// per-row parity checks against that external corpus instead of the
/// in-repo copy. The large real-binary TSVs such a tree may also carry
/// are not consumed by these suites.
func decodeCorpusTSVPath(family: String) -> String {
    if let external = ProcessInfo.processInfo.environment["IRIS_DECODE_CORPUS"] {
        return URL(fileURLWithPath: external)
            .appendingPathComponent("decode-\(family)/synthetic.tsv").path
    }
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // Decode
        .deletingLastPathComponent() // IrisTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // <package root>
    return root.appendingPathComponent("Tests/Fixtures/Decode/synthetic-\(family).tsv").path
}

// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0

import Foundation

func decodeCorpusTSVPath(
    family: String,
    externalRoot: String? = ProcessInfo.processInfo.environment["IRIS_DECODE_CORPUS"],
) -> String {
    if let externalRoot {
        return URL(fileURLWithPath: externalRoot)
            .appendingPathComponent("decode-\(family)/synthetic.tsv").path
    }
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    return root.appendingPathComponent("Tests/Fixtures/Decode/synthetic-\(family).tsv").path
}

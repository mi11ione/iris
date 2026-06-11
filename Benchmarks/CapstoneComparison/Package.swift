// swift-tools-version: 6.0
// Copyright (c) 2026 Roman Zhuzhgov
// Licensed under the Apache License, Version 2.0
//
// The Capstone comparison — its OWN package, two levels below the
// root, so the third-party dependency (capstone-swift) can NEVER enter
// the published `iris` package graph (the comparison harness may
// depend on third-party packages because benchmarks are not the
// library).
//
// Requirements: libcapstone v5 discoverable via pkg-config (macOS:
// `brew install capstone`; Ubuntu: `apt install libcapstone-dev
// pkg-config`; or a from-source prefix exported as
// PKG_CONFIG_PATH=<prefix>/lib/pkgconfig — see README.md). The
// capstone-swift `next` branch is the v5-compatible line (the repo has
// no v5 tag); pinned by revision for reproducibility.
//
//     swift run -c release iris-vs-capstone

import PackageDescription

let package = Package(
    name: "iris-capstone-comparison",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../.."),
        .package(
            url: "https://github.com/zydeco/capstone-swift",
            revision: "2d2a387e7165dbc033cccfef280f69c8bc55f7c3",
        ),
    ],
    targets: [
        .executableTarget(
            name: "iris-vs-capstone",
            dependencies: [
                .product(name: "Iris", package: "iris"),
                .product(name: "Capstone", package: "capstone-swift"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6),
            ],
        ),
    ],
)
